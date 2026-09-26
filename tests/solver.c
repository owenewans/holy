#include "solve.h"

#include <assert.h>
#include <stdio.h>

int main(void)
{
    const char *b_provides[] = {"package:local:b"};
    const char *c_provides[] = {"package:local:c"};
    struct holy_solver_requirement a_requires[] = {
        {"package:local:b", NULL}
    };
    struct holy_solver_item items[] = {
        {"artifact-a", NULL, 0, a_requires, 1},
        {"artifact-b", b_provides, 1, NULL, 0},
        {"artifact-c", c_provides, 1, NULL, 0}
    };
    int selected[3] = {9, 9, 9};
    assert(holy_solve_exact(items, 3, "artifact-a", selected) == 1);
    assert(selected[0] && selected[1] && !selected[2]);
    items[1].provides_count = 0;
    assert(holy_solve_exact(items, 3, "artifact-a", selected) == 2);
    assert(!selected[0] && !selected[1] && !selected[2]);
    a_requires[0].alternative = "package:local:c";
    assert(holy_solve_exact(items, 3, "artifact-a", selected) == 1);
    assert(selected[0] && !selected[1] && selected[2]);
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
