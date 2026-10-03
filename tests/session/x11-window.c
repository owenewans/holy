/* a small X11 helper for the GUI rows: it finds a window by title, sends it a key through
 * XTEST and writes a window image out as a portable pixmap, so a case can compare what a
 * client drew before and after an input event without a compositor screenshot tool. the
 * image is a PPM because reading one needs no library. */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>
#include <X11/extensions/XTest.h>

/* a modern client sets _NET_WM_NAME and leaves WM_NAME empty, so the name is read the way a
 * window manager reads it and only the legacy property is the fallback */
static char *window_title(Display *display, Window window)
{
    Atom atom = XInternAtom(display, "_NET_WM_NAME", True);
    if (atom != None) {
        XTextProperty text;
        memset(&text, 0, sizeof text);
        if (XGetTextProperty(display, window, &text, atom) && text.value && text.value[0]) {
            char *name = strdup((const char *)text.value);
            XFree(text.value);
            return name;
        }
        if (text.value)
            XFree(text.value);
    }
    char *name = NULL;
    if (XFetchName(display, window, &name) && name && name[0])
        return name;
    if (name)
        XFree(name);
    return NULL;
}

static Window find_by_title(Display *display, Window window, const char *needle, int depth)
{
    char *name = window_title(display, window);
    Window found = 0;
    if (name) {
        if (strstr(name, needle))
            found = window;
        free(name);
    }
    if (found || depth > 8)
        return found;
    Window root, parent, *children = NULL;
    unsigned int count = 0;
    if (!XQueryTree(display, window, &root, &parent, &children, &count))
        return 0;
    unsigned int i;
    for (i = 0; i < count && !found; i++)
        found = find_by_title(display, children[i], needle, depth + 1);
    if (children)
        XFree(children);
    return found;
}

static int list_titles(Display *display, Window window, int depth)
{
    if (depth > 8)
        return 0;
    char *name = window_title(display, window);
    if (name) {
        printf("window %lu title %s\n", (unsigned long)window, name);
        free(name);
    }
    Window root, parent, *children = NULL;
    unsigned int count = 0;
    if (!XQueryTree(display, window, &root, &parent, &children, &count))
        return 0;
    unsigned int i;
    for (i = 0; i < count; i++)
        list_titles(display, children[i], depth + 1);
    if (children)
        XFree(children);
    return 0;
}

static int send_key(Display *display, Window window, const char *name)
{
    KeySym symbol = XStringToKeysym(name);
    if (symbol == NoSymbol) {
        fprintf(stderr, "x11-window: %s is not a key this X server knows\n", name);
        return 1;
    }
    KeyCode code = XKeysymToKeycode(display, symbol);
    if (code == 0) {
        fprintf(stderr, "x11-window: no keycode for %s\n", name);
        return 1;
    }
    int event_base = 0, error_base = 0, major = 0, minor = 0;
    if (!XTestQueryExtension(display, &event_base, &error_base, &major, &minor)) {
        fprintf(stderr, "x11-window: the server has no XTEST extension\n");
        return 1;
    }
    XSetInputFocus(display, window, RevertToParent, CurrentTime);
    XFlush(display);
    /* the focus change has to reach the server before the key it should deliver */
    struct timespec settle = {0, 200000000};
    nanosleep(&settle, NULL);
    XTestFakeKeyEvent(display, code, True, 0);
    XTestFakeKeyEvent(display, code, False, 0);
    XFlush(display);
    printf("x11-window sent key=%s keycode=%u to window %lu\n", name, (unsigned)code,
           (unsigned long)window);
    return 0;
}

static int screenshot(Display *display, Window window, const char *path)
{
    XWindowAttributes geometry;
    if (!XGetWindowAttributes(display, window, &geometry)) {
        fprintf(stderr, "x11-window: XGetWindowAttributes: no geometry\n");
        return 1;
    }
    if (geometry.width <= 0 || geometry.height <= 0) {
        fprintf(stderr, "x11-window: the window has no area\n");
        return 1;
    }
    XImage *image = XGetImage(display, window, 0, 0, geometry.width, geometry.height, AllPlanes,
                              ZPixmap);
    if (!image) {
        fprintf(stderr, "x11-window: XGetImage: nothing to read\n");
        return 1;
    }
    FILE *stream = fopen(path, "wb");
    if (!stream) {
        fprintf(stderr, "x11-window: fopen %s\n", path);
        image->f.destroy_image(image);
        return 1;
    }
    const int width = geometry.width, height = geometry.height;
    fprintf(stream, "P6\n%d %d\n255\n", width, height);
    int x, y;
    unsigned char *row = malloc((size_t)width * 3);
    if (!row) {
        fprintf(stderr, "x11-window: malloc: out of memory\n");
        fclose(stream);
        image->f.destroy_image(image);
        return 1;
    }
    for (y = 0; y < geometry.height; y++) {
        for (x = 0; x < geometry.width; x++) {
            unsigned long pixel = XGetPixel(image, x, y);
            row[x * 3 + 0] = (unsigned char)((pixel >> 16) & 0xff);
            row[x * 3 + 1] = (unsigned char)((pixel >> 8) & 0xff);
            row[x * 3 + 2] = (unsigned char)(pixel & 0xff);
        }
        if (fwrite(row, 1, (size_t)width * 3, stream) != (size_t)width * 3) {
            fprintf(stderr, "x11-window: fwrite: short write\n");
            free(row);
            fclose(stream);
            image->f.destroy_image(image);
            return 1;
        }
    }
    free(row);
    fclose(stream);
    image->f.destroy_image(image);
    printf("x11-window captured %dx%d from window %lu into %s\n", geometry.width,
           geometry.height, (unsigned long)window, path);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
                "usage: x11-window list | find TITLE | send-key TITLE KEYNAME | shot TITLE FILE\n");
        return 2;
    }
    Display *display = XOpenDisplay(NULL);
    if (!display) {
        fprintf(stderr, "x11-window: XOpenDisplay: no session\n");
        return 1;
    }
    const char *command = argv[1];
    int status = 0;
    if (!strcmp(command, "list")) {
        status = list_titles(display, DefaultRootWindow(display), 0);
    } else if (argc == 3 && !strcmp(command, "find")) {
        Window window = find_by_title(display, DefaultRootWindow(display), argv[2], 0);
        if (!window) {
            fprintf(stderr, "x11-window: no window is titled with %s\n", argv[2]);
            status = 1;
        } else
            printf("%lu\n", (unsigned long)window);
    } else if (argc == 4 && !strcmp(command, "send-key")) {
        Window window = find_by_title(display, DefaultRootWindow(display), argv[2], 0);
        if (!window) {
            fprintf(stderr, "x11-window: no window is titled with %s\n", argv[2]);
            status = 1;
        } else
            status = send_key(display, window, argv[3]);
    } else if (argc == 4 && !strcmp(command, "shot")) {
        Window window;
        if (!strcmp(argv[2], "root"))
            window = DefaultRootWindow(display);
        else if (argv[2][0] >= '0' && argv[2][0] <= '9')
            window = (Window)strtoul(argv[2], NULL, 10);
        else
            window = find_by_title(display, DefaultRootWindow(display), argv[2], 0);
        if (!window) {
            fprintf(stderr, "x11-window: no window matches %s\n", argv[2]);
            status = 1;
        } else
            status = screenshot(display, window, argv[3]);
    } else {
        fprintf(stderr, "x11-window: %s does not match the arguments given\n", command);
        status = 2;
    }
    XCloseDisplay(display);
    return status;
}
