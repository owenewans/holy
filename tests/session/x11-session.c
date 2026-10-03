/* an X11 client that proves three things in one process: a session accepted it, it painted,
 * and an input event came back through the server. it fills its window with a known colour
 * and reads a pixel back, asks the server to focus it, generates a key event with XTEST and
 * waits for that same key to arrive at its own event loop. a client that never gets the key
 * fails, so a row cannot pass on a window existing. */
/* the fixture is compiled as strict c11, so the sleep calls it needs are asked for by name
 * rather than by relying on a GNU default */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>
#include <X11/extensions/XTest.h>

#define SIDE 64

/* usleep left POSIX in 2008, so the wait is nanosleep with a milliseconds argument */
static void nap(long milliseconds)
{
    struct timespec wait;
    wait.tv_sec = milliseconds / 1000;
    wait.tv_nsec = (milliseconds % 1000) * 1000000L;
    nanosleep(&wait, NULL);
}

int main(int argc, char **argv)
{
    const char *name;
    long limit_ms = 5000;
    Display *display;
    int screen;
    Window window;
    XSetWindowAttributes window_attributes;
    Colormap colours;
    XColor colour;
    GC context;
    XEvent event;
    KeySym symbol;
    int attempts;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: x11-session KEYNAME [TIMEOUT-MS]\n");
        return 2;
    }
    name = argv[1];
    if (argc == 3) {
        limit_ms = strtol(argv[2], NULL, 10);
        if (limit_ms < 100 || limit_ms > 120000)
            return 2;
    }
    display = XOpenDisplay(NULL);
    if (!display) {
        fprintf(stderr, "x11-session: XOpenDisplay: the session refused a client\n");
        return 1;
    }
    screen = DefaultScreen(display);
    colours = XCreateColormap(display, RootWindow(display, screen), DefaultVisual(display, screen),
                              AllocNone);
    memset(&window_attributes, 0, sizeof window_attributes);
    window_attributes.colormap = colours;
    window_attributes.background_pixel = BlackPixel(display, screen);
    window_attributes.event_mask = ExposureMask | KeyPressMask | StructureNotifyMask;
    window = XCreateWindow(display, RootWindow(display, screen), 0, 0, SIDE, SIDE, 0,
                           DefaultDepth(display, screen), InputOutput,
                           DefaultVisual(display, screen),
                           CWColormap | CWBackPixel | CWEventMask, &window_attributes);
    if (!window) {
        fprintf(stderr, "x11-session: XCreateWindow: no window\n");
        XCloseDisplay(display);
        return 1;
    }
    char title[64];
    snprintf(title, sizeof title, "holy-matrix %s", name);
    XStoreName(display, window, title);
    XMapWindow(display, window);
    XFlush(display);

    /* the paint waits for the window to be on the server, since a fill before the map is
     * not a client that drew anything */
    int mapped = 0;
    for (attempts = 0; attempts < 200 && !mapped; attempts++) {
        if (!XPending(display)) {
            nap(10);
            continue;
        }
        XNextEvent(display, &event);
        if (event.type == MapNotify)
            mapped = 1;
    }
    if (!mapped) {
        fprintf(stderr, "x11-session: the window was never mapped\n");
        XDestroyWindow(display, window);
        XCloseDisplay(display);
        return 1;
    }
    memset(&colour, 0, sizeof colour);
    colour.red = 0x2000;
    colour.green = 0x8000;
    colour.blue = 0xe000;
    colour.flags = DoRed | DoGreen | DoBlue;
    XAllocColor(display, colours, &colour);
    context = XCreateGC(display, window, 0, NULL);
    XSetForeground(display, context, colour.pixel);
    XFillRectangle(display, window, context, 0, 0, SIDE, SIDE);
    XFlush(display);
    XImage *image = XGetImage(display, window, SIDE / 2, SIDE / 2, 1, 1, AllPlanes, ZPixmap);
    unsigned long back = image ? XGetPixel(image, 0, 0) : 0;
    if (image)
        image->f.destroy_image(image);
    printf("x11-session window=%lu size=%dx%d pixel=%08lx\n", (unsigned long)window, SIDE, SIDE,
           back);
    if (back != colour.pixel) {
        fprintf(stderr, "x11-session: the readback pixel is not the one that was filled\n");
        XFreeGC(display, context);
        XDestroyWindow(display, window);
        XCloseDisplay(display);
        return 1;
    }

    symbol = XStringToKeysym(name);
    if (symbol == NoSymbol) {
        fprintf(stderr, "x11-session: %s is not a key this X server knows\n", name);
        XFreeGC(display, context);
        XDestroyWindow(display, window);
        XCloseDisplay(display);
        return 1;
    }
    KeyCode code = XKeysymToKeycode(display, symbol);
    if (code == 0) {
        fprintf(stderr, "x11-session: no keycode for %s\n", name);
        XFreeGC(display, context);
        XDestroyWindow(display, window);
        XCloseDisplay(display);
        return 1;
    }
    int event_base = 0, error_base = 0, major = 0, minor = 0;
    /* libXtst writes through every out parameter here, so the query gets five real slots
     * rather than the nulls that a header signature invites */
    if (!XTestQueryExtension(display, &event_base, &error_base, &major, &minor)) {
        fprintf(stderr, "x11-session: the server has no XTEST extension\n");
        XFreeGC(display, context);
        XDestroyWindow(display, window);
        XCloseDisplay(display);
        return 1;
    }
    XSetInputFocus(display, window, RevertToParent, CurrentTime);
    XFlush(display);
    nap(100);
    XTestFakeKeyEvent(display, code, True, 0);
    XTestFakeKeyEvent(display, code, False, 0);
    XFlush(display);

    int seen = 0;

    for (attempts = 0; attempts * 20 < limit_ms && !seen; attempts++) {
        while (XPending(display)) {
            XNextEvent(display, &event);
            if (event.type != KeyPress)
                continue;
            KeySym pressed = XLookupKeysym(&event.xkey, 0);
            if (pressed == symbol)
                seen = 1;
        }
        if (!seen)
            nap(20);
    }
    printf("x11-session key=%s keycode=%u delivered=%d\n", name, (unsigned)code, seen);
    XFreeGC(display, context);
    XDestroyWindow(display, window);
    XCloseDisplay(display);
    return seen ? 0 : 1;
}
