#include "solve.h"

#include <assert.h>
#include <stdio.h>

int main(void)
{
    const char *b_provides[] = {"package:local:b"};
    const char *c_provides[] = {"package:local:c"};
    const char *a_conflicts[] = {"package:local:b"};
    struct holy_solver_requirement a_requires[] = {
        {"package:local:b", NULL}
    };
    struct holy_solver_item items[] = {
        {"artifact-a", NULL, 0, a_requires, 1, NULL, 0},
        {"artifact-b", b_provides, 1, NULL, 0, NULL, 0},
        {"artifact-c", c_provides, 1, NULL, 0, NULL, 0}
    };
    int selected[3] = {9, 9, 9};
    assert(holy_solve_exact(items, 3, "artifact-a", selected) == 1);
    assert(selected[0] && selected[1] && !selected[2]);
    assert(holy_solve_exact_unique(items, 3, "artifact-a", selected) == 1);
    assert(selected[0] && selected[1] && !selected[2]);
    items[1].provides_count = 0;
    assert(holy_solve_exact(items, 3, "artifact-a", selected) == 2);
    assert(!selected[0] && !selected[1] && !selected[2]);
    a_requires[0].alternative = "package:local:c";
    assert(holy_solve_exact(items, 3, "artifact-a", selected) == 1);
    assert(selected[0] && !selected[1] && selected[2]);
    assert(holy_solve_exact_unique(items, 3, "artifact-a", selected) == 1);
    items[1].provides_count = 1;
    items[0].conflicts = a_conflicts;
    items[0].conflicts_count = 1;
    assert(holy_solve_exact(items, 3, "artifact-a", selected) == 1);
    assert(selected[0] && !selected[1] && selected[2]);
    assert(holy_solve_exact_unique(items, 3, "artifact-a", selected) == 1);
    a_requires[0].alternative = NULL;
    assert(holy_solve_exact(items, 3, "artifact-a", selected) == 2);
    assert(!selected[0] && !selected[1] && !selected[2]);
    items[0].conflicts = NULL;
    items[0].conflicts_count = 0;
    items[2].provides = b_provides;
    assert(holy_solve_exact_unique(items, 3, "artifact-a", selected) == 3);
    assert(!selected[0] && !selected[1] && !selected[2]);
    items[2].provides = c_provides;
    a_requires[0].alternative = "package:local:c";
    assert(holy_solve_exact_unique(items, 3, "artifact-a", selected) == 3);
    assert(!selected[0] && !selected[1] && !selected[2]);
    a_requires[0].alternative = NULL;
    a_requires[0].first = "package:local:b";
    {
        const struct holy_solver_requirement b_requires[] = {
            {"package:local:a", NULL}
        };
        const char *a_provides[] = {"package:local:a"};
        items[0].provides = a_provides;
        items[0].provides_count = 1;
        items[1].requires = b_requires;
        items[1].requires_count = 1;
        assert(holy_solve_exact(items, 3, "artifact-a", selected) == 1);
        assert(selected[0] && selected[1] && !selected[2]);
        items[1].requires = NULL;
        items[1].requires_count = 0;
        items[0].provides = NULL;
        items[0].provides_count = 0;
    }
    items[1].id = "artifact-a";
    assert(holy_solve_exact(items, 3, "artifact-a", selected) == 0);
    assert(!selected[0] && !selected[1] && !selected[2]);
    items[1].id = "artifact-b";
    selected[0] = 9;
    assert(holy_solve_exact(items, 3, "missing-artifact", selected) == 0);
    assert(!selected[0] && !selected[1] && !selected[2]);
    selected[0] = 9;
    assert(holy_solve_exact(items, 3, "", selected) == 0);
    assert(!selected[0] && !selected[1] && !selected[2]);
    puts("libsolv fixtures passed");
    return 0;
}
