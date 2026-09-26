#include "solve.h"

#include <solv/pool.h>
#include <solv/queue.h>
#include <solv/repo.h>
#include <solv/solvable.h>
#include <solv/solver.h>

#include <string.h>

static int solve(const struct holy_solver_item *items, size_t count,
                 const char *requested_id, int *selected, int unique)
{
    Pool *pool = NULL;
    Repo *repo;
    Solver *solver = NULL;
    Queue jobs;
    Id requested = 0;
    size_t i, j;
    int rc = 0;
    if (selected && count && count <= 100000)
        memset(selected, 0, count * sizeof *selected);
    if (!items || !selected || !requested_id || !*requested_id ||
        !count || count > 100000) return 0;
    for (i = 0; i < count; ++i) {
        if (!items[i].id || !*items[i].id ||
            (items[i].provides_count && !items[i].provides) ||
            (items[i].requires_count && !items[i].requires) ||
            (items[i].conflicts_count && !items[i].conflicts)) return 0;
        for (j = 0; j < i; ++j)
            if (!strcmp(items[i].id, items[j].id)) return 0;
    }
    pool = pool_create();
    if (!pool) return 0;
    repo = repo_create(pool, "holy-normalized");
    if (!repo) goto done;
    for (i = 0; i < count; ++i) {
        Id id = repo_add_solvable(repo);
        Solvable *s;
        if (!id) goto done;
        s = pool_id2solvable(pool, id);
        s->name = pool_str2id(pool, items[i].id, 1);
        s->evr = pool_str2id(pool, "0", 1);
        s->arch = pool_str2id(pool, "noarch", 1);
        if (!s->name || !s->evr || !s->arch) goto done;
        if (!strcmp(items[i].id, requested_id)) requested = id;
        for (j = 0; j < items[i].provides_count; ++j) {
            Id capability;
            if (!items[i].provides[j] || !*items[i].provides[j]) goto done;
            capability = pool_str2id(pool, items[i].provides[j], 1);
            if (!capability) goto done;
            s->provides = repo_addid_dep(repo, s->provides, capability, 0);
        }
        for (j = 0; j < items[i].requires_count; ++j) {
            const struct holy_solver_requirement *req = &items[i].requires[j];
            Id dep, alternative;
            if (!req->first || !*req->first) goto done;
            dep = pool_str2id(pool, req->first, 1);
            if (!dep) goto done;
            if (req->alternative) {
                if (!*req->alternative) goto done;
                alternative = pool_str2id(pool, req->alternative, 1);
                if (!alternative) goto done;
                dep = pool_rel2id(pool, dep, alternative, REL_OR, 1);
                if (!dep) goto done;
            }
            s->requires = repo_addid_dep(repo, s->requires, dep, 0);
        }
        for (j = 0; j < items[i].conflicts_count; ++j) {
            Id dep;
            if (!items[i].conflicts[j] || !*items[i].conflicts[j]) goto done;
            dep = pool_str2id(pool, items[i].conflicts[j], 1);
            if (!dep) goto done;
            s->conflicts = repo_addid_dep(repo, s->conflicts, dep, 0);
        }
    }
    if (!requested) goto done;
    repo_internalize(repo);
    pool_createwhatprovides(pool);
    solver = solver_create(pool);
    if (!solver) goto done;
    queue_init(&jobs);
    queue_push2(&jobs, SOLVER_INSTALL | SOLVER_SOLVABLE, requested);
    if (solver_solve(solver, &jobs)) rc = 2;
    else {
        for (i = 0; i < count; ++i)
            selected[i] = solver_get_decisionlevel(solver, repo->start + (Id)i) > 0;
        rc = 1;
        if (unique) for (i = 0; i < count; ++i) {
            Solver *trial;
            int problems;
            if (!selected[i] || repo->start + (Id)i == requested) continue;
            queue_push2(&jobs, SOLVER_ERASE | SOLVER_SOLVABLE,
                        repo->start + (Id)i);
            trial = solver_create(pool);
            if (!trial) { rc = 0; queue_pop(&jobs); queue_pop(&jobs); break; }
            problems = solver_solve(trial, &jobs);
            solver_free(trial);
            queue_pop(&jobs);
            queue_pop(&jobs);
            if (!problems) { rc = 3; break; }
        }
        if (rc != 1) memset(selected, 0, count * sizeof *selected);
    }
    queue_free(&jobs);
done:
    if (solver) solver_free(solver);
    if (pool) pool_free(pool);
    return rc;
}

int holy_solve_exact(const struct holy_solver_item *items, size_t count,
                     const char *requested_id, int *selected)
{
    return solve(items, count, requested_id, selected, 0);
}

int holy_solve_exact_unique(const struct holy_solver_item *items, size_t count,
                            const char *requested_id, int *selected)
{
    return solve(items, count, requested_id, selected, 1);
}
