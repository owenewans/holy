/* recipe manifest parsing and the build runner; see man/holy-recipe.5 */
#define _XOPEN_SOURCE 700
#include "recipe.h"
#include "config.h"
#include "elf.h"
#include "fetch.h"
#include "pack.h"
#include "version.h"

#include <archive.h>
#include <archive_entry.h>
#include <openssl/evp.h>
#include <ctype.h>
#include <stdarg.h>
#include <stddef.h>
#include <elf.h>
#define _DEFAULT_SOURCE 1
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct recipe_source {
    char *name, *url, *hash;
};

struct recipe_depend {
    char *kind, *name, *relation, *version;
};

struct recipe_output {
    char *name, *kind;
};

struct recipe_split {
    char *output, *pattern;
};

struct recipe_hook {
    char *interpreter, *path;
};

struct recipe_config {
    char *path;
    int mutable;
};

struct recipe_step {
    char *phase, *tag, *body, *file;
    char **argv;
    size_t argc;
    size_t length;
    size_t line;
};

struct recipe {
    char *format, *name, *version, *release, *arch, *libc, *summary;
    char *homepage, *license, *build_target, *extra;
    struct recipe_source *sources;
    size_t source_count;
    struct recipe_depend *depends;
    size_t depend_count;
    struct recipe_depend *build_depends;
    size_t build_depend_count;
    struct recipe_output *outputs;
    size_t output_count;
    struct recipe_split *splits;
    size_t split_count;
    struct recipe_hook *hook_install;
    size_t hook_install_count;
    struct recipe_hook *hook_remove;
    size_t hook_remove_count;
    struct recipe_config *configs;
    size_t config_count;
    struct recipe_step *steps;
    size_t step_count;
    char *text;
    size_t text_length;
};

static const char *const phases[] = {
    "fetch", "unpack", "prepare", "configure", "build", "check", "package", "split"
};

static int remove_tree(const char *path);

static void recipe_free(struct recipe *r)
{
    size_t i, j;
    free(r->format); free(r->name); free(r->version); free(r->release);
    free(r->arch); free(r->libc); free(r->summary); free(r->homepage);
    free(r->license); free(r->build_target); free(r->extra); free(r->text);
    for (i = 0; i < r->source_count; ++i) {
        free(r->sources[i].name); free(r->sources[i].url); free(r->sources[i].hash);
    }
    for (i = 0; i < r->depend_count; ++i) {
        free(r->depends[i].kind); free(r->depends[i].name);
        free(r->depends[i].relation); free(r->depends[i].version);
    }
    for (i = 0; i < r->build_depend_count; ++i) {
        free(r->build_depends[i].kind); free(r->build_depends[i].name);
        free(r->build_depends[i].relation); free(r->build_depends[i].version);
    }
    for (i = 0; i < r->output_count; ++i) {
        free(r->outputs[i].name); free(r->outputs[i].kind);
    }
    for (i = 0; i < r->split_count; ++i) {
        free(r->splits[i].output); free(r->splits[i].pattern);
    }
    for (i = 0; i < r->hook_install_count; ++i) {
        free(r->hook_install[i].interpreter); free(r->hook_install[i].path);
    }
    for (i = 0; i < r->hook_remove_count; ++i) {
        free(r->hook_remove[i].interpreter); free(r->hook_remove[i].path);
    }
    for (i = 0; i < r->config_count; ++i) free(r->configs[i].path);
    free(r->configs);
    for (i = 0; i < r->step_count; ++i) {
        free(r->steps[i].phase); free(r->steps[i].tag); free(r->steps[i].body);
        free(r->steps[i].file);
        for (j = 0; j < r->steps[i].argc; ++j) free(r->steps[i].argv[j]);
        free(r->steps[i].argv);
    }
    free(r->sources); free(r->depends); free(r->build_depends);
    free(r->outputs); free(r->splits); free(r->hook_install);
    free(r->hook_remove); free(r->steps);
    memset(r, 0, sizeof *r);
}

static int label(const char *value, size_t limit)
{
    const unsigned char *p = (const unsigned char *)value;
    size_t n = value ? strlen(value) : 0;
    if (!n || n >= limit || !isalnum(*p)) return 0;
    for (; *p; ++p)
        if (!isalnum(*p) && *p != '.' && *p != '_' && *p != '+' && *p != '-') return 0;
    return 1;
}

static int digest(const char *value)
{
    return value && strlen(value) == 64 && strspn(value, "0123456789abcdef") == 64;
}

static int safe_path(const char *value)
{
    const char *p = value;
    if (!value || !*value || *value == '/') return 0;
    while (*p) {
        size_t length = strcspn(p, "/");
        if (!length || (length == 1 && *p == '.') || (length == 2 && p[0] == '.' && p[1] == '.'))
            return 0;
        p += length;
        if (*p == '/') ++p;
    }
    return 1;
}

static int problem(const char *file, size_t line, const char *fmt, ...)
{
    char message[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(message, sizeof message, fmt, ap);
    va_end(ap);
    fprintf(stderr, "holypkg: %s:%zu: %s\n", file, line, message);
    return 2;
}

static char *joined(const char *directory, const char *name)
{
    size_t a = strlen(directory), b = strlen(name);
    char *out;
    if (a > SIZE_MAX - b - 2) return NULL;
    out = malloc(a + b + 2);
    if (!out) return NULL;
    memcpy(out, directory, a);
    out[a] = '/';
    memcpy(out + a + 1, name, b + 1);
    return out;
}

static int phase_index(const char *name)
{
    size_t i;
    for (i = 0; i < sizeof phases / sizeof *phases; ++i)
        if (!strcmp(phases[i], name)) return (int)i;
    return -1;
}

static int append_depend(struct recipe_depend **list, size_t *count,
                         char **tokens, size_t tokens_count)
{
    struct recipe_depend *grown = realloc(*list, (*count + 1) * sizeof **list);
    if (!grown) return 0;
    *list = grown;
    memset(&grown[*count], 0, sizeof grown[*count]);
    if (tokens_count == 2 && !strncmp(tokens[0], "cmd:", 4)) {
        grown[*count].kind = strdup("command");
        grown[*count].name = strdup(tokens[0] + 4);
    } else {
        grown[*count].kind = strdup("package");
        grown[*count].name = strdup(tokens[0]);
    }
    if (!grown[*count].kind || !grown[*count].name) return 0;
    if (tokens_count >= 3) {
        grown[*count].relation = strdup(tokens[1]);
        grown[*count].version = strdup(tokens[2]);
        if (!grown[*count].relation || !grown[*count].version) return 0;
    } else {
        grown[*count].relation = strdup("any");
        grown[*count].version = strdup("-");
        if (!grown[*count].relation || !grown[*count].version) return 0;
    }
    ++*count;
    return 1;
}

static int parse_step(struct recipe *recipe, const char *header, size_t length,
                      const char *body, size_t body_length, const char *file,
                      size_t line)
{
    char **tokens = NULL;
    size_t count = 0, i, block = 0;
    char *error = NULL;
    struct recipe_step *step, *grown;
    int ok = 0;
    if (!holy_lex(header, length, &tokens, &count, file, line, &error)) {
        fprintf(stderr, "holypkg: %s\n", error ? error : "invalid step header");
        free(error);
        return 2;
    }
    if (count < 4 || (strcmp(tokens[0], "step") && strcmp(tokens[0], "step-file"))) {
        holy_tokens_free(tokens, count);
        return problem(file, line, "step needs a phase, an interpreter and <<TAG or a script path");
    }
    if (phase_index(tokens[1]) < 0) {
        holy_tokens_free(tokens, count);
        return problem(file, line, "unknown phase %s", tokens[1]);
    }
    if (!strcmp(tokens[0], "step")) {
        size_t tag_length = strlen(tokens[count - 1]);
        if (tag_length < 3 || strncmp(tokens[count - 1], "<<", 2)) {
            holy_tokens_free(tokens, count);
            return problem(file, line, "step block needs a <<TAG terminator");
        }
        block = count - 1;
    }
    if (recipe->step_count >= 256) {
        holy_tokens_free(tokens, count);
        return problem(file, line, "too many steps");
    }
    grown = realloc(recipe->steps, (recipe->step_count + 1) * sizeof *recipe->steps);
    if (!grown) { holy_tokens_free(tokens, count); return 1; }
    recipe->steps = grown;
    step = &recipe->steps[recipe->step_count];
    memset(step, 0, sizeof *step);
    step->line = line;
    step->phase = strdup(tokens[1]);
    step->argc = block ? block - 2 : count - 3;
    if (block) {
        step->tag = strdup(tokens[count - 1] + 2);
        step->body = malloc(body_length + 1);
        if (step->body) {
            memcpy(step->body, body, body_length);
            step->body[body_length] = 0;
            step->length = body_length;
        }
    } else {
        step->file = strdup(tokens[count - 1]);
        if (!step->argc) step->argc = 1;
    }
    if (!step->phase || (block ? !step->tag || !step->body : !step->file)) goto done;
    if (!step->argc) goto done;
    step->argv = calloc(step->argc + 1, sizeof *step->argv);
    if (!step->argv) goto done;
    for (i = 0; i < step->argc; ++i) {
        if (block) step->argv[i] = strdup(tokens[i + 2]);
        else step->argv[i] = strdup(i + 2 < count - 1 ? tokens[i + 2] : tokens[count - 1]);
        if (!step->argv[i]) goto done;
    }
    ok = 1;
done:
    if (!ok) {
        free(step->phase); free(step->tag); free(step->body); free(step->file);
        for (i = 0; i < step->argc; ++i) free(step->argv[i]);
        free(step->argv);
        memset(step, 0, sizeof *step);
    }
    holy_tokens_free(tokens, count);
    if (!ok) return problem(file, line, "invalid step");
    ++recipe->step_count;
    return 0;
}

static int parse_recipe(const char *path, struct recipe *recipe)
{
    char *text = NULL;
    size_t length = 0, offset = 0, line = 0;
    FILE *file = fopen(path, "rb");
    int result = 2;
    if (!file) {
        fprintf(stderr, "holypkg: recipe unavailable: %s\n", path);
        return 6;
    }
    if (fseek(file, 0, SEEK_END) || (length = (size_t)ftell(file)) > 4 * 1024 * 1024 ||
        fseek(file, 0, SEEK_SET)) goto done;
    text = malloc(length + 1);
    if (!text) { result = 1; goto done; }
    if (fread(text, 1, length, file) != length) goto done;
    text[length] = 0;
    while (offset < length) {
        char *start = text + offset, *end = memchr(start, '\n', length - offset);
        size_t size;
        char **tokens = NULL;
        size_t count = 0;
        char *error = NULL;
        if (!end) { result = problem(path, line + 1, "unterminated line"); goto done; }
        size = (size_t)(end - start);
        offset += size + 1;
        ++line;
        if (!size || start[0] == '#') continue;
        if (!strncmp(start, "step ", 5) || !strncmp(start, "step-file ", 10)) {
            char *cursor = end + 1, *stop = NULL;
            size_t remaining = length - offset, body = 0;
            char *tag = NULL;
            if (strncmp(start, "step ", 5)) {
                result = parse_step(recipe, start, size, NULL, 0, path, line);
                if (result) goto done;
                continue;
            }
            if (!holy_lex(start, size, &tokens, &count, path, line, &error)) {
                fprintf(stderr, "holypkg: %s\n", error ? error : "invalid step header");
                free(error); goto done;
            }
            if (count < 4 || strncmp(tokens[count - 1], "<<", 2)) {
                holy_tokens_free(tokens, count);
                result = problem(path, line, "step needs a phase, an interpreter and <<TAG");
                goto done;
            }
            tag = tokens[count - 1] + 2;
            while (body < remaining) {
                char *row = cursor + body;
                char *row_end = memchr(row, '\n', remaining - body);
                size_t row_size = row_end ? (size_t)(row_end - row) : remaining - body;
                if (row_size == strlen(tag) && !memcmp(row, tag, row_size)) {
                    stop = cursor + body;
                    body += row_size + (row_end ? 1 : 0);
                    break;
                }
                body += row_size + (row_end ? 1 : 0);
            }
            if (!stop) {
                holy_tokens_free(tokens, count);
                result = problem(path, line, "step block is not terminated by %s", tag);
                goto done;
            }
            result = parse_step(recipe, start, size, cursor,
                                (size_t)(stop - cursor), path, line);
            holy_tokens_free(tokens, count);
            if (result) goto done;
            offset = (size_t)((cursor + body) - text);
            line = 0;
            for (size_t i = 0; i < offset; ++i) if (text[i] == '\n') ++line;
            continue;
        }
        if (!holy_lex(start, size, &tokens, &count, path, line, &error)) {
            fprintf(stderr, "holypkg: %s\n", error ? error : "invalid manifest line");
            free(error);
            goto done;
        }
        if (!count) { holy_tokens_free(tokens, count); continue; }
        {
            static const struct { const char *key; size_t offset; } free_text[] = {
                { "summary", offsetof(struct recipe, summary) },
                { "homepage", offsetof(struct recipe, homepage) },
                { "license", offsetof(struct recipe, license) }
            };
            size_t index, k;
            for (index = 0; index < sizeof free_text / sizeof *free_text; ++index) {
                char **slot, *joined_text;
                size_t used = 1;
                if (strcmp(tokens[0], free_text[index].key)) continue;
                if (count < 2) {
                    result = problem(path, line, "%s needs text", tokens[0]);
                    break;
                }
                slot = (char **)((char *)recipe + free_text[index].offset);
                for (k = 1; k < count; ++k) used += strlen(tokens[k]) + 1;
                joined_text = malloc(used);
                if (!joined_text) { result = 1; break; }
                strcpy(joined_text, tokens[1]);
                for (k = 2; k < count; ++k) {
                    strcat(joined_text, " ");
                    strcat(joined_text, tokens[k]);
                }
                if (*slot) {
                    result = problem(path, line, "duplicate %s", tokens[0]);
                    free(joined_text);
                } else {
                    *slot = joined_text;
                    result = 0;
                }
                break;
            }
            if (index < sizeof free_text / sizeof *free_text) goto next_line;
        }
        {
            static const struct { const char *key; size_t offset; } scalars[] = {
                { "format", offsetof(struct recipe, format) },
                { "name", offsetof(struct recipe, name) },
                { "version", offsetof(struct recipe, version) },
                { "release", offsetof(struct recipe, release) },
                { "build-target", offsetof(struct recipe, build_target) },
                { "arch", offsetof(struct recipe, arch) },
                { "libc", offsetof(struct recipe, libc) }
            };
            size_t index;
            for (index = 0; index < sizeof scalars / sizeof *scalars; ++index) {
                char **slot;
                if (strcmp(tokens[0], scalars[index].key)) continue;
                if (count != 2) {
                    result = problem(path, line, "%s needs one value", tokens[0]);
                    break;
                }
                slot = (char **)((char *)recipe + scalars[index].offset);
                if (*slot) result = problem(path, line, "duplicate %s", tokens[0]);
                else if (!(*slot = strdup(tokens[1]))) result = 1;
                else result = 0;
                break;
            }
            if (index < sizeof scalars / sizeof *scalars) goto next_line;
        }
        if (!strcmp(tokens[0], "source") && count == 3) {
            struct recipe_source *grown = realloc(recipe->sources,
                                       (recipe->source_count + 1) * sizeof *recipe->sources);
            if (!grown) { holy_tokens_free(tokens, count); result = 1; goto done; }
            recipe->sources = grown;
            memset(&grown[recipe->source_count], 0, sizeof grown[0]);
            grown[recipe->source_count].name = strdup(tokens[1]);
            grown[recipe->source_count].url = strdup(tokens[2]);
            if (!grown[recipe->source_count].name || !grown[recipe->source_count].url) {
                holy_tokens_free(tokens, count); result = 1; goto done;
            }
            ++recipe->source_count;
        } else if (!strcmp(tokens[0], "source-sha256") && count == 3) {
            size_t i;
            for (i = 0; i < recipe->source_count; ++i)
                if (!strcmp(recipe->sources[i].name, tokens[1])) break;
            if (i == recipe->source_count)
                result = problem(path, line, "source-sha256 names an undeclared source %s", tokens[1]);
            else if (!digest(tokens[2]))
                result = problem(path, line, "source-sha256 needs 64 hexadecimal digits");
            else if (recipe->sources[i].hash)
                result = problem(path, line, "duplicate source-sha256 for %s", tokens[1]);
            else if (!(recipe->sources[i].hash = strdup(tokens[2]))) { result = 1; }
            else result = 0;
        } else if (!strcmp(tokens[0], "build-depend") && count >= 2 && count <= 4) {
            result = append_depend(&recipe->build_depends, &recipe->build_depend_count,
                                   tokens + 1, count - 1) ? 0 : 1;
        } else if (!strcmp(tokens[0], "depend") && count >= 2 && count <= 4) {
            result = append_depend(&recipe->depends, &recipe->depend_count,
                                   tokens + 1, count - 1) ? 0 : 1;
        } else if (!strcmp(tokens[0], "output") && count == 3) {
            struct recipe_output *grown = realloc(recipe->outputs,
                                       (recipe->output_count + 1) * sizeof *recipe->outputs);
            size_t i;
            if (!grown) { holy_tokens_free(tokens, count); result = 1; goto done; }
            recipe->outputs = grown;
            memset(&grown[recipe->output_count], 0, sizeof grown[0]);
            grown[recipe->output_count].name = strdup(tokens[1]);
            grown[recipe->output_count].kind = strdup(tokens[2]);
            if (!grown[recipe->output_count].name || !grown[recipe->output_count].kind) {
                holy_tokens_free(tokens, count); result = 1; goto done;
            }
            for (i = 0; i < recipe->output_count; ++i)
                if (!strcmp(recipe->outputs[i].name, tokens[1])) {
                    result = problem(path, line, "duplicate output %s", tokens[1]);
                    break;
                }
            if (!result) ++recipe->output_count;
        } else if (!strcmp(tokens[0], "config") && (count == 2 || count == 3)) {
            struct recipe_config *grown = realloc(recipe->configs,
                                       (recipe->config_count + 1) * sizeof *recipe->configs);
            size_t i;
            if (!grown) { holy_tokens_free(tokens, count); result = 1; goto done; }
            recipe->configs = grown;
            memset(&grown[recipe->config_count], 0, sizeof grown[0]);
            grown[recipe->config_count].path = strdup(tokens[1]);
            grown[recipe->config_count].mutable = count == 3 && !strcmp(tokens[2], "mutable");
            if (!grown[recipe->config_count].path ||
                (count == 3 && !grown[recipe->config_count].mutable)) {
                holy_tokens_free(tokens, count);
                free(grown[recipe->config_count].path);
                result = 2;
                goto done;
            }
            for (i = 0; i < recipe->config_count; ++i)
                if (!strcmp(recipe->configs[i].path, tokens[1])) {
                    result = problem(path, line, "duplicate config %s", tokens[1]);
                    break;
                }
            if (!result) ++recipe->config_count;
        } else if (!strcmp(tokens[0], "split") && count == 3) {
            struct recipe_split *grown = realloc(recipe->splits,
                                       (recipe->split_count + 1) * sizeof *recipe->splits);
            size_t i;
            if (!grown) { holy_tokens_free(tokens, count); result = 1; goto done; }
            recipe->splits = grown;
            memset(&grown[recipe->split_count], 0, sizeof grown[0]);
            grown[recipe->split_count].output = strdup(tokens[1]);
            grown[recipe->split_count].pattern = strdup(tokens[2]);
            if (!grown[recipe->split_count].output || !grown[recipe->split_count].pattern) {
                holy_tokens_free(tokens, count); result = 1; goto done;
            }
            for (i = 0; i < recipe->output_count; ++i)
                if (!strcmp(recipe->outputs[i].name, tokens[1])) break;
            if (i == recipe->output_count) {
                result = problem(path, line, "split names an undeclared output %s", tokens[1]);
            } else {
                ++recipe->split_count;
                result = 0;
            }
        } else if ((!strcmp(tokens[0], "hook-install") || !strcmp(tokens[0], "hook-remove")) &&
                   count == 3) {
            struct recipe_hook **list = !strcmp(tokens[0], "hook-install") ?
                &recipe->hook_install : &recipe->hook_remove;
            size_t *total = !strcmp(tokens[0], "hook-install") ?
                &recipe->hook_install_count : &recipe->hook_remove_count;
            struct recipe_hook *grown = realloc(*list, (*total + 1) * sizeof **list);
            if (!grown) { holy_tokens_free(tokens, count); result = 1; goto done; }
            *list = grown;
            memset(&grown[*total], 0, sizeof grown[0]);
            grown[*total].interpreter = strdup(tokens[1]);
            grown[*total].path = strdup(tokens[2]);
            if (!grown[*total].interpreter || !grown[*total].path) {
                holy_tokens_free(tokens, count); result = 1; goto done;
            }
            ++*total;
            result = 0;
        } else if (!strncmp(tokens[0], "x-", 2) && count >= 2) {
            size_t i;
            size_t used = recipe->extra ? strlen(recipe->extra) : 0;
            char *text_line = malloc(strlen(tokens[0]) + 2);
            if (!text_line) { holy_tokens_free(tokens, count); result = 1; goto done; }
            sprintf(text_line, "%s ", tokens[0]);
            for (i = 1; i < count; ++i) {
                char *grown = realloc(text_line, strlen(text_line) + strlen(tokens[i]) + 2);
                if (!grown) { free(text_line); holy_tokens_free(tokens, count); result = 1; goto done; }
                text_line = grown;
                strcat(text_line, tokens[i]);
                strcat(text_line, " ");
            }
            {
                char *joined_extra = realloc(recipe->extra, used + strlen(text_line) + 1);
                if (!joined_extra) { free(text_line); holy_tokens_free(tokens, count); result = 1; goto done; }
                recipe->extra = joined_extra;
                memcpy(recipe->extra + used, text_line, strlen(text_line) + 1);
            }
            free(text_line);
            result = 0;
        } else {
            result = problem(path, line, "unknown key %s", tokens[0]);
        }
next_line:
        holy_tokens_free(tokens, count);
        if (result) goto done;
    }
    result = 0;
done:
    fclose(file);
    if (!result) { recipe->text = text; recipe->text_length = length; }
    else free(text);
    return result;
}

static int validate_recipe(struct recipe *recipe, const char *path)
{
    size_t i;
    if (!recipe->format || strcmp(recipe->format, "holy-recipe-1")) {
        fprintf(stderr, "holypkg: %s: format must be holy-recipe-1\n", path);
        return 2;
    }
    if (!label(recipe->name, 256) || !label(recipe->version, 256) ||
        !label(recipe->release, 64)) {
        fprintf(stderr, "holypkg: %s: name, version and release are required labels\n", path);
        return 2;
    }
    if (!recipe->arch || !label(recipe->arch, 64) || !recipe->libc ||
        !label(recipe->libc, 64)) {
        fprintf(stderr, "holypkg: %s: arch and libc are required labels\n", path);
        return 2;
    }
    if (!recipe->output_count) {
        fprintf(stderr, "holypkg: %s: at least one output is required\n", path);
        return 2;
    }
    for (i = 0; i < recipe->source_count; ++i) {
        const char *url = recipe->sources[i].url;
        if (!label(recipe->sources[i].name, 256) || !*url) {
            fprintf(stderr, "holypkg: %s: source needs a name and an input\n", path);
            return 2;
        }
        if (strstr(url, "://") && !recipe->sources[i].hash) {
            fprintf(stderr, "holypkg: %s: network source %s needs source-sha256\n",
                    path, recipe->sources[i].name);
            return 2;
        }
        if (recipe->sources[i].hash && !digest(recipe->sources[i].hash)) {
            fprintf(stderr, "holypkg: %s: source %s has a malformed digest\n",
                    path, recipe->sources[i].name);
            return 2;
        }
        if (strstr(url, "://") && strncmp(url, "https://", 8)) {
            fprintf(stderr, "holypkg: %s: source %s needs https\n", path, recipe->sources[i].name);
            return 2;
        }
    }
    for (i = 0; i < recipe->depend_count; ++i) {
        if (!recipe->depends[i].name[0]) {
            fprintf(stderr, "holypkg: %s: depend needs a name\n", path);
            return 2;
        }
    }
    for (i = 0; i < recipe->hook_install_count; ++i) {
        if (recipe->hook_install[i].interpreter[0] != '/' ||
            !safe_path(recipe->hook_install[i].path)) {
            fprintf(stderr, "holypkg: %s: hook-install needs an absolute interpreter and a relative script\n", path);
            return 2;
        }
    }
    for (i = 0; i < recipe->hook_remove_count; ++i) {
        if (recipe->hook_remove[i].interpreter[0] != '/' ||
            !safe_path(recipe->hook_remove[i].path)) {
            fprintf(stderr, "holypkg: %s: hook-remove needs an absolute interpreter and a relative script\n", path);
            return 2;
        }
    }
    for (i = 0; i < recipe->config_count; ++i)
        if (!safe_path(recipe->configs[i].path)) {
            fprintf(stderr, "holypkg: %s: config %s needs a relative payload path\n",
                    path, recipe->configs[i].path);
            return 2;
        }
    return 0;
}

struct run_paths {
    char *work, *src, *build, *dest, *out, *sources;
};

static void run_paths_free(struct run_paths *paths)
{
    free(paths->work); free(paths->src); free(paths->build); free(paths->dest);
    free(paths->out); free(paths->sources);
    memset(paths, 0, sizeof *paths);
}

/* zero on failure, matching the other local helpers in this file. */
/* copies one pinned local object to a named path inside the build root. */
static int stage_local(const char *source, const char *target, const char *expected)
{
    char *directory = strdup(target), *slash;
    unsigned char buffer[65536], digest_bytes[32];
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    unsigned length;
    ssize_t got;
    int in = -1, out = -1, ok = 0;
    if (!directory || !(slash = strrchr(directory, '/'))) goto done;
    *slash = 0;
    {
        size_t length = strlen(directory), index;
        for (index = 1; index <= length; ++index) {
            char saved;
            if (index < length && directory[index] != '/') continue;
            saved = directory[index];
            directory[index] = 0;
            if (mkdir(directory, 0700) && errno != EEXIST) { directory[index] = saved; goto done; }
            directory[index] = saved;
        }
    }
    in = open(source, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (in < 0 || !context || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1) goto done;
    out = open(target, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (out < 0) goto done;
    while ((got = read(in, buffer, sizeof buffer)) > 0) {
        if (EVP_DigestUpdate(context, buffer, (size_t)got) != 1 ||
            write(out, buffer, (size_t)got) != got) goto done;
    }
    if (got < 0 || EVP_DigestFinal_ex(context, digest_bytes, &length) != 1 || length != 32) goto done;
    {
        char actual[65];
        size_t i;
        for (i = 0; i < 32; ++i) snprintf(actual + i * 2, 3, "%02x", digest_bytes[i]);
        if (expected && strcmp(actual, expected)) goto done;
    }
    ok = 1;
done:
    if (out >= 0 && close(out) && ok) ok = 0;
    if (in >= 0) close(in);
    EVP_MD_CTX_free(context);
    free(directory);
    return ok;
}

static int populate(const char *work)
{
    static const char *const names[] = { "src", "build", "dest", "out", "sources" };
    char *path = NULL;
    size_t i;
    int result = 0;
    if (mkdir(work, 0700) && errno != EEXIST) {
        fprintf(stderr, "holypkg: build root unavailable: %s\n", work);
        return 1;
    }
    for (i = 0; i < sizeof names / sizeof *names; ++i) {
        free(path);
        path = joined(work, names[i]);
        if (!path || (mkdir(path, 0700) && errno != EEXIST)) {
            fprintf(stderr, "holypkg: build directory unavailable: %s/%s\n", work, names[i]);
            result = 1;
            goto done;
        }
    }
done:
    free(path);
    return result;
}

static int unpack_archive(const char *archive_path, const char *target)
{
    struct archive *a = archive_read_new();
    struct archive_entry *entry;
    char buffer[65536];
    la_ssize_t got;
    unsigned long long total = 0;
    int ok = 0;
    if (!a) return 0;
    if (archive_read_support_filter_all(a) != ARCHIVE_OK ||
        archive_read_support_format_tar(a) != ARCHIVE_OK ||
        archive_read_support_format_raw(a) != ARCHIVE_OK ||
        archive_read_open_filename(a, archive_path, 65536) != ARCHIVE_OK) goto done;
    while ((got = archive_read_data(a, buffer, sizeof buffer)) > 0) {
        if (total > 1024ULL * 1024 * 1024 - (unsigned long long)got) goto done;
        total += (unsigned long long)got;
    }
    if (got) goto done;
    archive_read_free(a);
    a = archive_read_new();
    if (!a) return 0;
    if (archive_read_support_filter_all(a) != ARCHIVE_OK ||
        archive_read_support_format_tar(a) != ARCHIVE_OK ||
        archive_read_open_filename(a, archive_path, 65536) != ARCHIVE_OK ||
        archive_read_next_header(a, &entry) != ARCHIVE_OK) {
        archive_read_free(a);
        return 0;
    }
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        char *path = NULL;
        const char *name = archive_entry_pathname(entry);
        int fd;
        if (!safe_path(name)) { archive_read_free(a); return 0; }
        path = joined(target, name);
        if (!path) { archive_read_free(a); return 1; }
        if (archive_entry_filetype(entry) == AE_IFDIR) {
            if (mkdir(path, 0700) && errno != EEXIST) { free(path); archive_read_free(a); return 0; }
        } else if (archive_entry_filetype(entry) == AE_IFLNK) {
            const char *link = archive_entry_symlink(entry);
            if (!link || !safe_path(link) || symlink(link, path)) { free(path); archive_read_free(a); return 0; }
        } else if (archive_entry_filetype(entry) == AE_IFREG) {
            la_ssize_t copied;
            mode_t mode = archive_entry_perm(entry);
            fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, mode & 0777);
            if (fd < 0) { free(path); archive_read_free(a); return 0; }
            while ((copied = archive_read_data(a, buffer, sizeof buffer)) > 0)
                if (write(fd, buffer, (size_t)copied) != (ssize_t)copied) {
                    close(fd); free(path); archive_read_free(a); return 0;
                }
            if (copied < 0 || close(fd)) { free(path); archive_read_free(a); return 0; }
        }
        free(path);
    }
    ok = 1;
done:
    archive_read_free(a);
    return ok;
}

static int write_file(const char *path, const char *body, size_t length, unsigned mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, mode);
    size_t used = 0;
    if (fd < 0) return 0;
    while (used < length) {
        ssize_t written = write(fd, body + used, length - used);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) { close(fd); return 0; }
        used += (size_t)written;
    }
    return !close(fd);
}

static int run_step(const struct recipe_step *step, const char *work, const char *recipe_dir,
                    const struct recipe *recipe, const char *environment, unsigned jobs,
                    int approve_all, int noninteractive, int *approve_rest)
{
    char *script = NULL, *argv[64] = {0};
    char work_buffer[4096], src_buffer[4096], build_buffer[4096], dest_buffer[4096];
    char out_buffer[4096], jobs_buffer[32], target_buffer[256];
    const char *cwd = work;
    size_t i;
    pid_t child;
    int status = 0, result = 1;
    if (step->body) {
        script = joined(work, "step-script");
        if (!script || !write_file(script, step->body, step->length, 0700)) {
            fprintf(stderr, "holypkg: recipe step %zu script unavailable\n", step->line);
            free(script);
            return 1;
        }
    } else {
        char *candidate = safe_path(step->file) ? joined(recipe_dir, step->file) : NULL;
        struct stat st;
        if (!candidate || stat(candidate, &st) || !S_ISREG(st.st_mode) ||
            st.st_size > 4 * 1024 * 1024) {
            fprintf(stderr, "holypkg: recipe step %zu script unavailable: %s\n",
                    step->line, step->file);
            free(candidate);
            return 1;
        }
        script = candidate;
    }
    for (i = 0; i < step->argc && i + 1 < sizeof argv / sizeof *argv; ++i)
        argv[i] = step->argv[i];
    argv[i] = script;
    argv[i + 1] = NULL;
    if (!strcmp(step->phase, "build") || !strcmp(step->phase, "package") ||
        !strcmp(step->phase, "split") || !strcmp(step->phase, "check")) {
        if (strlen(work) + 8 > sizeof build_buffer) { free(script); return 1; }
        snprintf(build_buffer, sizeof build_buffer, "%s/build", work);
        cwd = build_buffer;
    }
    snprintf(work_buffer, sizeof work_buffer, "%s", work);
    snprintf(src_buffer, sizeof src_buffer, "%s/src", work);
    snprintf(dest_buffer, sizeof dest_buffer, "%s/dest", work);
    snprintf(out_buffer, sizeof out_buffer, "%s/out", work);
    snprintf(jobs_buffer, sizeof jobs_buffer, "%u", jobs ? jobs : 1);
    snprintf(target_buffer, sizeof target_buffer, "%s-linux-%s",
             recipe->arch ? recipe->arch : "any", recipe->libc ? recipe->libc : "nolibc");
    if (!*approve_rest && !approve_all) {
        char answer[16];
        if (noninteractive || !isatty(STDIN_FILENO)) {
            fprintf(stderr, "holypkg: decision-required recipe step %s; pass --yes after review\n",
                    step->phase);
            free(script);
            return 3;
        }
        printf("phase %s interpreter %s\n", step->phase, step->argc ? step->argv[0] : "-");
        printf("argv");
        for (i = 0; i < step->argc; ++i) printf(" %s", step->argv[i]);
        printf(" %s\n", script);
        printf("cwd %s uid %ld\n", cwd, (long)getuid());
        if (step->body) fwrite(step->body, 1, step->length, stdout);
        fflush(stdout);
        if (!fgets(answer, sizeof answer, stdin)) { free(script); return 3; }
        if (answer[0] == 'a' || answer[0] == 'A') *approve_rest = 1;
        else if (answer[0] != 'y' && answer[0] != 'Y') { free(script); return 3; }
    }
    child = fork();
    if (child < 0) { free(script); return 1; }
    if (!child) {
        const char *library = getenv("LD_LIBRARY_PATH");
        if (chdir(cwd)) _exit(126);
        setenv("HOLY_WORK", work_buffer, 1);
        setenv("HOLY_SRC", src_buffer, 1);
        setenv("HOLY_BUILD", build_buffer, 1);
        setenv("HOLY_DEST", dest_buffer, 1);
        setenv("HOLY_OUT", out_buffer, 1);
        setenv("HOLY_ARCH", recipe->arch ? recipe->arch : "any", 1);
        setenv("HOLY_LIBC", recipe->libc ? recipe->libc : "nolibc", 1);
        setenv("HOLY_JOBS", jobs_buffer, 1);
        setenv("HOLY_BUILD_TARGET", target_buffer, 1);
        setenv("HOLY_HOST_TARGET", target_buffer, 1);
        setenv("HOLY_TARGET", target_buffer, 1);
        if (library) setenv("LD_LIBRARY_PATH", library, 1);
        if (!strcmp(environment, "clean")) {
            unsetenv("HOME");
            setenv("PATH", "/usr/bin:/bin", 1);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) continue;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) result = 0;
    else {
        fprintf(stderr, "holypkg: recipe step %s failed with status %d\n",
                step->phase, WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        result = WIFEXITED(status) && WEXITSTATUS(status) == 127 ? 6 : 1;
    }
    if (script && strncmp(script, work, strlen(work))) unlink(script);
    free(script);
    return result;
}

struct payload_entry {
    char *path;
    char *link;
    char *group;
    unsigned int mode;
    unsigned long long size;
    int directory;
};

struct payload {
    struct payload_entry *items;
    size_t count;
    char *groups[8];
    size_t group_count;
};

static void payload_free(struct payload *payload)
{
    size_t i;
    for (i = 0; i < payload->count; ++i) {
        free(payload->items[i].path);
        free(payload->items[i].link);
    }
    for (i = 0; i < payload->group_count; ++i) free(payload->groups[i]);
    free(payload->items);
    memset(payload, 0, sizeof *payload);
}

static int payload_add(struct payload *payload, const char *path, const char *link,
                       const char *group, unsigned int mode,
                       unsigned long long size, int directory)
{
    struct payload_entry *grown = realloc(payload->items, (payload->count + 1) * sizeof *grown);
    if (!grown) return 0;
    payload->items = grown;
    memset(&grown[payload->count], 0, sizeof grown[0]);
    grown[payload->count].path = strdup(path);
    grown[payload->count].link = link ? strdup(link) : NULL;
    grown[payload->count].group = group ? strdup(group) : NULL;
    grown[payload->count].mode = mode;
    grown[payload->count].size = size;
    grown[payload->count].directory = directory;
    if (!grown[payload->count].path || (link && !grown[payload->count].link) ||
        (group && !grown[payload->count].group)) return 0;
    ++payload->count;
    return 1;
}

static int entry_order(const void *left, const void *right)
{
    return strcmp(((const struct payload_entry *)left)->path,
                  ((const struct payload_entry *)right)->path);
}

static int collect_payload(const char *root, const char *relative, struct payload *payload)
{
    char *path = relative && *relative ? joined(root, relative) : strdup(root);
    DIR *dir;
    struct dirent *item;
    int result = 1;
    if (!path) return 0;
    dir = opendir(path);
    if (!dir) { free(path); return 0; }
    while ((item = readdir(dir))) {
        char *child_relative = NULL, *child_path = NULL;
        struct stat st;
        unsigned long long size = 0;
        int ok = 1;
        if (!strcmp(item->d_name, ".") || !strcmp(item->d_name, "..")) continue;
        if (!safe_path(item->d_name)) goto done;
        child_relative = relative && *relative ?
            joined(relative, item->d_name) : strdup(item->d_name);
        child_path = joined(path, item->d_name);
        if (!child_relative || !child_path) { ok = 0; goto next; }
        if (lstat(child_path, &st)) goto next;
        if (S_ISDIR(st.st_mode)) {
            if (!payload_add(payload, child_relative, NULL, NULL,
                             (unsigned int)(st.st_mode & 07777), 0, 1)) ok = 0;
            else ok = collect_payload(root, child_relative, payload);
        } else if (S_ISLNK(st.st_mode)) {
            char target[4096];
            ssize_t length = readlink(child_path, target, sizeof target - 1);
            if (length <= 0) goto next;
            target[length] = 0;
            if (!safe_path(target)) {
                fprintf(stderr, "holypkg: unsafe payload symlink %s -> %s\n", child_relative, target);
                ok = 0;
            } else if (!payload_add(payload, child_relative, target, NULL, 0777, 0, 0)) ok = 0;
        } else if (S_ISREG(st.st_mode)) {
            const char *group = "noarch-nolibc";
            struct holy_elf_info info;
            if (!holy_elf_read(child_path, &info)) {
                const char *machine = holy_elf_machine(&info);
                const char *runtime = holy_elf_runtime(&info);
                char buffer[64];
                if (!strcmp(machine, "unknown") || !strcmp(runtime, "unknown")) {
                    fprintf(stderr, "holypkg: unclassified ELF in build output: %s\n", child_relative);
                    holy_elf_free(&info);
                    ok = 0;
                } else {
                    size_t k;
                    snprintf(buffer, sizeof buffer, "%s-%s", machine, runtime);
                    for (k = 0; k < payload->group_count; ++k)
                        if (!strcmp(payload->groups[k], buffer)) break;
                    if (k == payload->group_count) {
                        if (k >= sizeof payload->groups / sizeof *payload->groups) {
                            fprintf(stderr, "holypkg: too many ABI groups in one build\n");
                            holy_elf_free(&info);
                            ok = 0;
                        } else {
                            payload->groups[k] = strdup(buffer);
                            if (!payload->groups[k]) { holy_elf_free(&info); ok = 0; }
                            else ++payload->group_count;
                        }
                    }
                    if (ok) group = payload->groups[k];
                }
                holy_elf_free(&info);
            }
            if (ok) {
                size = (unsigned long long)st.st_size;
                ok = payload_add(payload, child_relative, NULL, group,
                                 (unsigned int)(st.st_mode & 07777), size, 0);
            }
        }
next:
        free(child_relative);
        free(child_path);
        if (!ok) { result = 0; break; }
    }
done:
    closedir(dir);
    free(path);
    return result;
}

static int copy_into(const char *dest_tree, const char *source_root,
                     const struct payload_entry *entry)
{
    char *target = joined(dest_tree, entry->path);
    char *parent = NULL, *slash;
    int result = 1, fd;
    if (!target) return 0;
    parent = strdup(target);
    if (!parent) { free(target); return 0; }
    slash = strrchr(parent, '/');
    if (!slash) { free(target); free(parent); return 0; }
    *slash = 0;
    {
        size_t length = strlen(parent), index;
        for (index = 1; index <= length; ++index) {
            char saved;
            if (index < length && parent[index] != '/') continue;
            saved = parent[index];
            parent[index] = 0;
            if (mkdir(parent, 0700) && errno != EEXIST) {
                fprintf(stderr, "holypkg: build directory unavailable: %s\n", parent);
                parent[index] = saved;
                result = 0;
                break;
            }
            parent[index] = saved;
        }
    }
    if (result && entry->directory) {
        if (mkdir(target, 0700) && errno != EEXIST) result = 0;
    } else if (result && entry->link) {
        if (symlink(entry->link, target)) result = 0;
    } else if (result) {
        char *source = joined(source_root, entry->path);
        unsigned char buffer[65536];
        ssize_t got;
        if (!source) result = 0;
        fd = result ? open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW) : -1;
        if (fd < 0) result = 0;
        else {
            int out = open(target, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
                           entry->mode & 0777);
            if (out < 0) result = 0;
            while (result && (got = read(fd, buffer, sizeof buffer)) > 0)
                if (write(out, buffer, (size_t)got) != got) result = 0;
            if (got < 0) result = 0;
            if (close(out)) result = 0;
        }
        if (fd >= 0) close(fd);
        free(source);
    }
    free(target);
    free(parent);
    return result;
}

static const char *output_for(const struct recipe *recipe, const char *path)
{
    size_t i;
    for (i = 0; i < recipe->split_count; ++i)
        if (!fnmatch(recipe->splits[i].pattern, path, 0)) return recipe->splits[i].output;
    return recipe->output_count ? recipe->outputs[0].name : NULL;
}

static void split_group(const char *group, char arch[64], char libc[64])
{
    char *dash;
    snprintf(arch, 64, "%s", group);
    dash = strchr(arch, '-');
    if (!dash) { snprintf(libc, 64, "nolibc"); return; }
    snprintf(libc, 64, "%s", dash + 1);
    *dash = 0;
}

static void token(FILE *out, const char *value)
{
    const unsigned char *p = (const unsigned char *)value;
    fputc('"', out);
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') fprintf(out, "\\%c", *p);
        else if (*p < 32 || *p >= 127) fprintf(out, "\\x%02x", *p);
        else fputc(*p, out);
    }
    fputc('"', out);
}

struct requirement {
    char kind[32], name[256], arch[64], libc[64], relation[16], version[128];
    char evidence[256];
};

static int requirement_line(FILE *out, unsigned index, const char *consumer,
                            const struct requirement *item)
{
    char id[96];
    snprintf(id, sizeof id, "%s-req-%u", consumer, index);
    fputs("require ", out);
    token(out, id); fputc(' ', out);
    token(out, consumer); fputc(' ', out);
    token(out, item->kind); fputc(' ', out);
    token(out, item->name); fputc(' ', out);
    token(out, item->arch); fputc(' ', out);
    token(out, item->libc); fputc(' ', out);
    token(out, item->relation); fputc(' ', out);
    token(out, item->version); fputc(' ', out);
    token(out, item->evidence); fputc(' ', out);
    fputs("\"holy-recipe\"\n", out);
    return ferror(out) ? 0 : 1;
}

static int hook_digest(const char *dest, const char *relative, char hash[65])
{
    char *path = joined(dest, relative);
    struct stat st;
    int fd = -1, ok = 0;
    unsigned char buffer[65536], digest_bytes[32];
    ssize_t got;
    size_t used = 0;
    EVP_MD_CTX *context = NULL;
    unsigned length;
    if (!path) return 0;
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size > 1024 * 1024) goto done;
    context = EVP_MD_CTX_new();
    if (!context || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1) goto done;
    while ((got = read(fd, buffer, sizeof buffer)) > 0)
        if (EVP_DigestUpdate(context, buffer, (size_t)got) != 1) goto done;
    if (got < 0 || EVP_DigestFinal_ex(context, digest_bytes, &length) != 1 || length != 32) goto done;
    for (used = 0; used < 32; ++used) snprintf(hash + used * 2, 3, "%02x", digest_bytes[used]);
    ok = 1;
done:
    EVP_MD_CTX_free(context);
    if (fd >= 0) close(fd);
    free(path);
    return ok;
}

/* the packer writes flag none; a declared config path is rewritten in place. */
static int mark_config(const char *manifest, const struct recipe *recipe, const char *output_name)
{
    char *text = NULL, *rewritten = NULL;
    size_t length = 0, offset = 0, used = 0, i;
    FILE *out = NULL;
    FILE *input = fopen(manifest, "rb");
    int ok = 0;
    if (!input) return 0;
    if (fseek(input, 0, SEEK_END) || (length = (size_t)ftell(input)) > 64 * 1024 * 1024 ||
        fseek(input, 0, SEEK_SET)) goto done;
    text = malloc(length + 1);
    if (!text || fread(text, 1, length, input) != length) goto done;
    text[length] = 0;
    out = open_memstream(&rewritten, &used);
    if (!out) goto done;
    while (offset < length) {
        char *start = text + offset, *end = memchr(start, '\n', length - offset);
        char **tokens = NULL;
        size_t count = 0, k;
        char *error = NULL;
        size_t size = end ? (size_t)(end - start) : length - offset;
        offset += size + (end ? 1 : 0);
        if (!holy_lex(start, size, &tokens, &count, "HOLY/files", 1, &error)) {
            free(error);
            holy_tokens_free(tokens, count);
            fclose(out);
            goto done;
        }
        if (!count) { holy_tokens_free(tokens, count); continue; }
        if (count >= 12 && !strcmp(tokens[0], "file")) {
            for (i = 0; i < recipe->config_count; ++i)
                if (!strcmp(recipe->configs[i].path, tokens[1])) {
                    fprintf(out, "file ");
                    token(out, tokens[1]);
                    for (k = 2; k < 9; ++k) fprintf(out, " %s", tokens[k]);
                    fprintf(out, " %s", recipe->configs[i].mutable ? "config,mutable" : "config");
                    for (k = 10; k < count; ++k) fprintf(out, " %s", tokens[k]);
                    fputc('\n', out);
                    break;
                }
            if (i < recipe->config_count) { holy_tokens_free(tokens, count); continue; }
        }
        fwrite(start, 1, size, out);
        if (end) fputc('\n', out);
        holy_tokens_free(tokens, count);
    }
    if (fflush(out) || ferror(out) || fclose(out)) { out = NULL; goto done; }
    out = NULL;
    input = freopen(manifest, "w", input);
    if (!input || fwrite(rewritten, 1, used, input) != used || fflush(input) ||
        fsync(fileno(input)) || fclose(input)) { input = NULL; goto done; }
    input = NULL;
    ok = 1;
done:
    if (out) fclose(out);
    if (input) fclose(input);
    free(text);
    free(rewritten);
    (void)output_name;
    return ok;
}

/* an output is grouped by the ABI facts of the files it actually receives. */
struct output_group {
    char name[64];
    int seen;
};

static int collect_output_groups(const struct recipe *recipe, const char *output_name,
                                 const struct payload *payload, struct output_group *groups,
                                 size_t limit)
{
    size_t i, k, used = 0;
    for (i = 0; i < payload->count; ++i) {
        const struct payload_entry *entry = &payload->items[i];
        const char *target = entry->directory ? NULL : output_for(recipe, entry->path);
        if (!entry->group || !target || strcmp(target, output_name)) continue;
        for (k = 0; k < used; ++k)
            if (!strcmp(groups[k].name, entry->group)) break;
        if (k == used) {
            if (used >= limit) return -1;
            snprintf(groups[used].name, sizeof groups[used].name, "%s", entry->group);
            groups[used].seen = 1;
            ++used;
        }
    }
    return (int)used;
}

static int emit_output(struct recipe *recipe, const char *group, const char *output_name,
                       const char *kind, const char *dest, const char *output_directory,
                       unsigned serial, int multi_group, const struct payload *payload,
                       struct requirement *requirements, size_t requirement_count,
                       const char **variants, size_t variant_count)
{
    char *tree = NULL, *holy = NULL, *files_path = NULL, *meta_path = NULL;
    char *deps_path = NULL, *provides_path = NULL, *hooks_path = NULL;
    char *origin_path = NULL, *transform_path = NULL, *artifact = NULL;
    char tree_name[64];
    char arch[64], libc[64];
    unsigned long long size = 0;
    size_t i, included = 0;
    int result = 1;
    if (!output_name) return 0;
    split_group(group, arch, libc);
    snprintf(tree_name, sizeof tree_name, "tree-%u", serial);
    tree = joined(output_directory, tree_name);
    if (!tree || mkdir(tree, 0700)) {
        fprintf(stderr, "holypkg: build output tree unavailable\n");
        goto done;
    }
    holy = joined(tree, "HOLY");
    if (!holy || mkdir(holy, 0700) || !(files_path = joined(holy, "files"))) goto done;
    {
        char *data = joined(tree, "DATA");
        if (!data || mkdir(data, 0700)) { free(data); goto done; }
        free(data);
    }
    {
        char *data = joined(tree, "DATA");
        if (!data) goto done;
        for (i = 0; i < payload->count; ++i) {
            const struct payload_entry *entry = &payload->items[i];
            const char *target;
            if (entry->directory) continue;
            target = output_for(recipe, entry->path);
            if (!target || strcmp(target, output_name)) continue;
            if (entry->group && strcmp(entry->group, group)) continue;
            if (!entry->group && multi_group) {
                /* a link or data file follows the first group that claims it */
                printf("ambiguous %s assigned to %s--%s\n", entry->path, output_name, group);
                continue;
            }
            if (!copy_into(data, dest, entry)) { free(data); goto done; }
            size += entry->size;
            ++included;
        }
        free(data);
    }
    if (!strcmp(kind, "metapackage")) {
        if (payload->count && !included && strcmp(output_name, recipe->outputs[0].name)) goto done;
    } else if (!included && strcmp(output_name, recipe->outputs[0].name)) {
        result = 0;
        goto done;
    }
    {
        /* the manifest generator refuses paths inside the tree it walks */
        char *manifest = joined(output_directory, "build-manifest");
        if (!manifest || !holy_generate_files(tree, manifest) ||
            rename(manifest, files_path)) {
            fprintf(stderr, "holypkg: manifest generation failed for %s\n", output_name);
            free(manifest);
            goto done;
        }
        free(manifest);
    }
    if (recipe->config_count && !mark_config(files_path, recipe, output_name)) {
        fprintf(stderr, "holypkg: config flags not applied for %s\n", output_name);
        goto done;
    }
    meta_path = joined(holy, "meta");
    deps_path = joined(holy, "deps");
    provides_path = joined(holy, "provides");
    hooks_path = joined(holy, "hooks");
    origin_path = joined(holy, "origin");
    transform_path = joined(holy, "transform");
    if (!meta_path || !deps_path || !provides_path || !hooks_path || !origin_path ||
        !transform_path) goto done;
    {
        FILE *out = fopen(meta_path, "w");
        if (!out) goto done;
        fputs("format holy-package-1\nname ", out); token(out, output_name);
        fputs("\nversion ", out); token(out, recipe->version);
        fputs("\nrelease ", out); token(out, recipe->release);
        fputs("\nos linux\narch ", out); token(out, arch);
        fputs("\nlibc ", out); token(out, libc);
        fputs("\nx-version-family holy\nx-build-target ", out);
        token(out, recipe->build_target ? recipe->build_target : "host");
        fputc('\n', out);
        fprintf(out, "installed-size %llu\n", size);
        if (recipe->summary) { fputs("summary ", out); token(out, recipe->summary); fputc('\n', out); }
        if (recipe->homepage) { fputs("homepage ", out); token(out, recipe->homepage); fputc('\n', out); }
        if (recipe->license) { fputs("license ", out); token(out, recipe->license); fputc('\n', out); }
        if (recipe->extra) fputs(recipe->extra, out);
        if (fclose(out)) goto done;
    }
    {
        FILE *out = fopen(deps_path, "w");
        if (!out) goto done;
        for (i = 0; i < requirement_count; ++i)
            if (!requirement_line(out, (unsigned)i, output_name, &requirements[i])) {
                fclose(out); goto done;
            }
        for (i = 0; i < variant_count; ++i) {
            struct requirement metapackage;
            memset(&metapackage, 0, sizeof metapackage);
            snprintf(metapackage.kind, sizeof metapackage.kind, "package");
            snprintf(metapackage.name, sizeof metapackage.name, "%s", variants[i]);
            snprintf(metapackage.arch, sizeof metapackage.arch, "%s", arch);
            snprintf(metapackage.libc, sizeof metapackage.libc, "any");
            snprintf(metapackage.relation, sizeof metapackage.relation, "any");
            snprintf(metapackage.version, sizeof metapackage.version, "-");
            snprintf(metapackage.evidence, sizeof metapackage.evidence, "holy-recipe-output");
            if (!requirement_line(out, (unsigned)(requirement_count + i), output_name, &metapackage)) {
                fclose(out); goto done;
            }
        }
        if (fclose(out)) goto done;
    }
    {
        char *data = joined(tree, "DATA");
        FILE *out = fopen(provides_path, "w");
        if (!data || !out) { free(data); if (out) fclose(out); goto done; }
        fprintf(out, "provide package \"%s\" any any \"-\" holy\n", output_name);
        for (i = 0; i < payload->count; ++i) {
            const struct payload_entry *entry = &payload->items[i];
            const char *target = entry->directory ? NULL : output_for(recipe, entry->path);
            struct holy_elf_info info;
            char *path;
            if (entry->directory || entry->link || !target || strcmp(target, output_name)) continue;
            if (entry->group && strcmp(entry->group, group)) continue;
            path = joined(data, entry->path);
            if (!path) { fclose(out); free(data); goto done; }
            if (!holy_elf_read(path, &info) && info.soname && !strchr(info.soname, '/') &&
                info.type == ET_DYN) {
                fprintf(out, "provide soname \"%s\" any any \"-\" holy\n", info.soname);
            }
            holy_elf_free(&info);
            free(path);
        }
        free(data);
        if (fclose(out)) goto done;
    }
    {
        FILE *out = fopen(hooks_path, "w");
        if (!out) goto done;
        for (i = 0; i < recipe->hook_install_count; ++i) {
            char hash[65];
            if (!hook_digest(dest, recipe->hook_install[i].path, hash)) { fclose(out); goto done; }
            fprintf(out, "hook postinstall \"%s\" \"%s\" sha256 %s\n",
                    recipe->hook_install[i].interpreter, recipe->hook_install[i].path, hash);
        }
        for (i = 0; i < recipe->hook_remove_count; ++i) {
            char hash[65];
            if (!hook_digest(dest, recipe->hook_remove[i].path, hash)) { fclose(out); goto done; }
            fprintf(out, "hook preremove \"%s\" \"%s\" sha256 %s\n",
                    recipe->hook_remove[i].interpreter, recipe->hook_remove[i].path, hash);
        }
        if (fclose(out)) goto done;
    }
    {
        FILE *out = fopen(origin_path, "w");
        if (!out) goto done;
        fputs("format holy-recipe-origin-1\nsource local-recipe\nverification built-locally\n"
              "converter holy-recipe-1\n", out);
        for (i = 0; i < recipe->source_count; ++i) {
            fprintf(out, "recipe-source %s ", recipe->sources[i].name);
            token(out, recipe->sources[i].url);
            if (recipe->sources[i].hash) fprintf(out, " sha256 %s", recipe->sources[i].hash);
            fputc('\n', out);
        }
        if (fclose(out)) goto done;
    }
    {
        FILE *out = fopen(transform_path, "w");
        if (!out) goto done;
        fprintf(out, "format holy-recipe-transform-1\nbuild-environment recorded\n");
        for (i = 0; i < recipe->build_depend_count; ++i) {
            fputs("build-depend ", out);
            token(out, recipe->build_depends[i].name); fputc('\n', out);
        }
        if (fclose(out)) goto done;
    }
    {
        char filename[512];
        snprintf(filename, sizeof filename, "%s--%s--%s.holy", output_name, arch, libc);
        artifact = joined(output_directory, filename);
        if (!artifact || !holy_pack(tree, artifact)) goto done;
    }
    printf("built %s--%s--%s %llu bytes %zu files\n", output_name, arch, libc, size, included);
    result = 0;
done:
    if (result) fprintf(stderr, "holypkg: build output %s failed\n", output_name);
    if (tree) remove_tree(tree);
    free(tree);
    free(holy); free(files_path); free(meta_path); free(deps_path);
    free(provides_path); free(hooks_path); free(origin_path); free(transform_path);
    free(artifact);
    return result;
}

static int remove_tree(const char *path)
{
    DIR *dir = opendir(path);
    struct dirent *item;
    int result = 0;
    if (!dir) return unlink(path) && errno == ENOENT;
    while ((item = readdir(dir))) {
        char *child;
        if (!strcmp(item->d_name, ".") || !strcmp(item->d_name, "..")) continue;
        child = joined(path, item->d_name);
        if (!child) { result = 1; break; }
        {
            struct stat st;
            if (!lstat(child, &st) && S_ISDIR(st.st_mode)) remove_tree(child);
            else unlink(child);
        }
        free(child);
    }
    closedir(dir);
    return result || rmdir(path);
}

int holy_recipe_build(const char *path, const char *environment, const char *work,
                      const char *output, unsigned jobs, int approve_all,
                      int noninteractive, int keep)
{
    struct recipe recipe = {0};
    struct run_paths paths = {0};
    struct payload payload = {0};
    struct requirement *requirements = NULL;
    size_t requirement_count = 0, requirement_capacity = 0, i, k;
    char *recipe_dir = NULL, *slash = NULL;
    int result = 1, approve_rest = 0;
    time_t started = time(NULL);
    if (!path || !environment || !output || !*output ||
        (strcmp(environment, "host") && strcmp(environment, "clean"))) {
        if (path && environment && !strcmp(environment, "vm")) {
            fprintf(stderr, "holypkg: vm builds need a booted Holy image and qemu-system; "
                    "no such environment is available\n");
            return 6;
        }
        fputs("usage: holypkg build RECIPE --output NEW_DIRECTORY "
              "[--environment host|clean|vm] [--work NEW_DIRECTORY] [--jobs N] "
              "[--yes] [--noninteractive] [--keep]\n", stderr);
        return 2;
    }
    if (mkdir(output, 0700) && errno != EEXIST) {
        fprintf(stderr, "holypkg: output directory unavailable: %s\n", output);
        return 1;
    }
    result = parse_recipe(path, &recipe);
    if (!result) result = validate_recipe(&recipe, path);
    if (result) goto done;
    recipe_dir = strdup(path);
    if (!recipe_dir) { result = 1; goto done; }
    slash = strrchr(recipe_dir, '/');
    if (slash) *slash = 0;
    else strcpy(recipe_dir, ".");
    if (work) {
        struct stat st;
        if (stat(work, &st) || !S_ISDIR(st.st_mode)) {
            fprintf(stderr, "holypkg: build root unavailable: %s\n", work);
            result = 6; goto done;
        }
    } else {
        char temporary[] = "/tmp/holy-recipe-XXXXXX";
        if (!mkdtemp(temporary)) {
            fprintf(stderr, "holypkg: build root unavailable\n");
            result = 6; goto done;
        }
        work = temporary;
    }
    if (populate(work)) { result = 1; goto done; }
    paths.work = strdup(work);
    paths.src = joined(work, "src");
    paths.build = joined(work, "build");
    paths.dest = joined(work, "dest");
    paths.out = joined(work, "out");
    paths.sources = joined(work, "sources");
    if (!paths.work || !paths.src || !paths.build || !paths.dest || !paths.out ||
        !paths.sources) { result = 1; goto done; }
    printf("recipe %s %s-%s environment %s work %s\n",
           recipe.name, recipe.version, recipe.release, environment, work);
    for (i = 0; i < recipe.source_count; ++i) {
        char filename[512], *target;
        const char *url = recipe.sources[i].url;
        int fetch_result;
        snprintf(filename, sizeof filename, "%s", recipe.sources[i].name);
        target = joined(paths.sources, filename);
        if (!target) { result = 1; goto done; }
        if (strstr(url, "://")) {
            fetch_result = recipe.sources[i].hash ?
                holy_fetch_https(url, recipe.sources[i].hash, target, NULL, 0) :
                0;
            if (fetch_result) {
                fprintf(stderr, "holypkg: source %s unavailable from %s (status %d)\n",
                        recipe.sources[i].name, url, fetch_result);
                free(target);
                result = fetch_result;
                goto done;
            }
        } else {
            char *local = *url == '/' ? strdup(url) :
                (safe_path(url) ? joined(recipe_dir, url) : NULL);
            if (!local || !*local || !stage_local(local, target, recipe.sources[i].hash)) {
                fprintf(stderr, "holypkg: source %s unavailable: %s\n",
                        recipe.sources[i].name, url);
                free(local); free(target);
                result = 6; goto done;
            }
            free(local);
        }
        printf("fetched %s sha256 %s\n", recipe.sources[i].name,
               recipe.sources[i].hash ? recipe.sources[i].hash : "unpinned");
        free(target);
    }
    for (i = 0; i < recipe.source_count; ++i) {
        char filename[512];
        struct stat st;
        int has_step = 0;
        snprintf(filename, sizeof filename, "%s", recipe.sources[i].name);
        for (k = 0; k < recipe.step_count; ++k)
            if (!strcmp(recipe.steps[k].phase, "unpack")) has_step = 1;
        if (has_step) continue;
        {
            char *archive_path = joined(paths.sources, filename);
            char *target = joined(paths.src, filename);
            if (!archive_path || !target) { free(archive_path); free(target); result = 1; goto done; }
            if (!stat(archive_path, &st) && S_ISREG(st.st_mode)) {
                if (!unpack_archive(archive_path, target) &&
                    !stage_local(archive_path, target, NULL)) {
                    fprintf(stderr, "holypkg: source %s could not enter the source tree\n",
                            recipe.sources[i].name);
                    free(archive_path); free(target);
                    result = 1; goto done;
                }
            }
            free(archive_path);
            free(target);
        }
    }
    for (k = 0; k < sizeof phases / sizeof *phases; ++k) {
        for (i = 0; i < recipe.step_count; ++i) {
            if (strcmp(recipe.steps[i].phase, phases[k])) continue;
            result = run_step(&recipe.steps[i], work, recipe_dir, &recipe, environment, jobs,
                              approve_all, noninteractive, &approve_rest);
            if (result) goto done;
        }
        if (k == 0 || k == 1) continue;
        if (k == 3 && !recipe.step_count) continue;
    }
    if (!collect_payload(paths.dest, NULL, &payload)) { result = 1; goto done; }
    qsort(payload.items, payload.count, sizeof *payload.items, entry_order);
    if (!payload.count) {
        fprintf(stderr, "holypkg: package phase installed no files into the destination\n");
        result = 1;
        goto done;
    }
    for (i = 0; i < payload.count; ++i) {
        const struct payload_entry *entry = &payload.items[i];
        struct holy_elf_info info;
        char *absolute;
        if (entry->directory || entry->link || !entry->group) continue;
        absolute = joined(paths.dest, entry->path);
        if (!absolute) { result = 1; goto done; }
        if (!holy_elf_read(absolute, &info)) {
            for (k = 0; k < info.needed_count; ++k) {
                struct requirement *grown;
                if (!info.needed[k][0] || strchr(info.needed[k], '/')) continue;
                if (requirement_count == requirement_capacity) {
                    size_t next = requirement_capacity ? requirement_capacity * 2 : 32;
                    grown = realloc(requirements, next * sizeof *grown);
                    if (!grown) { holy_elf_free(&info); free(absolute); result = 1; goto done; }
                    requirements = grown;
                    requirement_capacity = next;
                }
                memset(&requirements[requirement_count], 0, sizeof *grown);
                snprintf(requirements[requirement_count].kind,
                         sizeof requirements[requirement_count].kind, "soname");
                snprintf(requirements[requirement_count].name,
                         sizeof requirements[requirement_count].name, "%s", info.needed[k]);
                snprintf(requirements[requirement_count].arch,
                         sizeof requirements[requirement_count].arch, "%s",
                         recipe.arch ? recipe.arch : "any");
                snprintf(requirements[requirement_count].libc,
                         sizeof requirements[requirement_count].libc, "any");
                snprintf(requirements[requirement_count].relation,
                         sizeof requirements[requirement_count].relation, "any");
                snprintf(requirements[requirement_count].version,
                         sizeof requirements[requirement_count].version, "-");
                snprintf(requirements[requirement_count].evidence,
                         sizeof requirements[requirement_count].evidence, "%s", entry->path);
                ++requirement_count;
            }
            holy_elf_free(&info);
        }
        free(absolute);
    }
    for (i = 0; i < recipe.depend_count; ++i) {
        struct requirement *grown = realloc(requirements,
                                     (requirement_count + 1) * sizeof *grown);
        if (!grown) { result = 1; goto done; }
        requirements = grown;
        memset(&grown[requirement_count], 0, sizeof grown[0]);
        snprintf(grown[requirement_count].kind, sizeof grown[0].kind, "%s",
                 recipe.depends[i].kind);
        snprintf(grown[requirement_count].name, sizeof grown[0].name, "%s",
                 recipe.depends[i].name);
        snprintf(grown[requirement_count].arch, sizeof grown[0].arch, "any");
        snprintf(grown[requirement_count].libc, sizeof grown[0].libc, "any");
        snprintf(grown[requirement_count].relation, sizeof grown[0].relation, "%s",
                 recipe.depends[i].relation);
        snprintf(grown[requirement_count].version, sizeof grown[0].version, "%s",
                 recipe.depends[i].version);
        snprintf(grown[requirement_count].evidence, sizeof grown[0].evidence, "recipe-depend");
        ++requirement_count;
    }
    {
        const char *variants[8];
        size_t variant_count = 0;
        unsigned serial = 0;
        for (i = 0; i < payload.group_count; ++i)
            for (k = 0; k < recipe.output_count; ++k)
                if (!strcmp(recipe.outputs[k].kind, "metapackage")) {
                    char arch[64], libc[64], name[512];
                    split_group(payload.groups[i], arch, libc);
                    if (variant_count >= sizeof variants / sizeof *variants) break;
                    snprintf(name, sizeof name, "%s--%s--%s", recipe.outputs[k].name, arch, libc);
                    variants[variant_count] = name;
                    ++variant_count;
                }
        for (i = 0; i < recipe.output_count; ++i) {
            struct output_group groups[8];
            int group_count = collect_output_groups(&recipe, recipe.outputs[i].name,
                                                    &payload, groups,
                                                    sizeof groups / sizeof *groups);
            size_t g;
            if (group_count < 0) {
                fputs("holypkg: too many ABI groups in one output\n", stderr);
                result = 1; goto done;
            }
            if (!strcmp(recipe.outputs[i].kind, "metapackage")) {
                if (emit_output(&recipe, "noarch-nolibc", recipe.outputs[i].name,
                                recipe.outputs[i].kind, paths.dest, output, serial,
                                group_count > 1, &payload, requirements, requirement_count,
                                variants, variant_count)) { result = 1; goto done; }
                ++serial;
                continue;
            }
            if (!group_count) {
                printf("skipped %s no payload assigned\n", recipe.outputs[i].name);
                continue;
            }
            for (g = 0; g < (size_t)group_count; ++g) {
                if (emit_output(&recipe, groups[g].name, recipe.outputs[i].name,
                                recipe.outputs[i].kind, paths.dest, output, serial,
                                group_count > 1, &payload, requirements, requirement_count,
                                NULL, 0)) {
                    result = 1; goto done;
                }
                ++serial;
            }
        }
    }
    printf("build complete %zu files %zu requirements %lds\n",
           payload.count, requirement_count, (long)(time(NULL) - started));
    result = 0;
done:
    if (result && result != 1)
        fprintf(stderr, "holypkg: build failed (status %d)\n", result);
    if (work && !keep && !result) remove_tree(work);
    else if (work && keep) printf("build root kept %s\n", work);
    free(requirements);
    payload_free(&payload);
    run_paths_free(&paths);
    free(recipe_dir);
    recipe_free(&recipe);
    return result;
}
