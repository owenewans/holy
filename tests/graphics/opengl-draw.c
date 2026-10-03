/* an OpenGL fixture that draws rather than counting a context: it makes a core profile
 * context on the session display, renders a triangle into an FBO it owns, reads the pixels
 * back and checks the gradient the fragment shader computes. a context that exists proves
 * nothing about whether a driver drew anything, so the check is the readback. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <X11/Xlib.h>
/* the desktop GL headers expose only the 1.2 core unless they are asked for the rest */
#define GL_GLEXT_PROTOTYPES
#include <GL/glx.h>
#include <GL/gl.h>
#include <GL/glext.h>

#define SIDE 64

static const char *const vertex_source =
    "#version 330 core\n"
    "void main()\n"
    "{\n"
    "    vec2 points[3] = vec2[3](vec2(-1.0, -3.0), vec2(-1.0, 1.0), vec2(3.0, 1.0));\n"
    "    gl_Position = vec4(points[gl_VertexID], 0.0, 1.0);\n"
    "}\n";

static const char *const fragment_source =
    "#version 330 core\n"
    "out vec4 colour;\n"
    "void main()\n"
    "{\n"
    "    colour = vec4(gl_FragCoord.x / 64.0, gl_FragCoord.y / 64.0, 0.0, 1.0);\n"
    "}\n";

static GLuint compile(const GLenum type, const char *source)
{
    GLuint shader = glCreateShader(type);
    glShaderSource(shader, 1, &source, NULL);
    glCompileShader(shader);
    GLint compiled = GL_FALSE;
    glGetShaderiv(shader, GL_COMPILE_STATUS, &compiled);
    if (!compiled) {
        char log[2048];
        glGetShaderInfoLog(shader, sizeof log, NULL, log);
        fprintf(stderr, "opengl-draw: the shader did not compile: %s\n", log);
        glDeleteShader(shader);
        return 0;
    }
    return shader;
}

static int near(unsigned char value, float expected)
{
    float scaled = expected * 255.0f;
    float difference = (float)value - scaled;
    if (difference < 0)
        difference = -difference;
    return difference <= 2.0f;
}

int main(void)
{
    Display *display = XOpenDisplay(NULL);
    if (!display) {
        fprintf(stderr, "opengl-draw: XOpenDisplay: no display\n");
        return 1;
    }
    /* a composited session offers window framebuffer configurations and no pbuffer ones, so
     * the fixture draws into an FBO on an unmapped window and never presents anything. the
     * render type is left at its default, since the header set here has no GLX_RGBA_BIT_TYPE
     * and the rgba sizes below already say what the fixture needs */
    int attributes[] = {GLX_DRAWABLE_TYPE, GLX_WINDOW_BIT, GLX_RED_SIZE, 8, GLX_GREEN_SIZE, 8,
                        GLX_BLUE_SIZE, 8, GLX_ALPHA_SIZE, 8, GLX_DEPTH_SIZE, 0,
                        GLX_DOUBLEBUFFER, False, None};
    int count = 0;
    GLXFBConfig *configs = glXChooseFBConfig(display, DefaultScreen(display), attributes, &count);
    if (!configs || count < 1) {
        fprintf(stderr, "opengl-draw: glXChooseFBConfig: no framebuffer configuration\n");
        XFree(configs);
        XCloseDisplay(display);
        return 1;
    }
    XVisualInfo *visual = glXGetVisualFromFBConfig(display, configs[0]);
    if (!visual) {
        fprintf(stderr, "opengl-draw: glXGetVisualFromFBConfig: no visual\n");
        XFree(configs);
        XCloseDisplay(display);
        return 1;
    }
    XSetWindowAttributes window_attributes;
    memset(&window_attributes, 0, sizeof window_attributes);
    window_attributes.colormap =
        XCreateColormap(display, RootWindow(display, visual->screen), visual->visual, AllocNone);
    window_attributes.event_mask = 0;
    Window window = XCreateWindow(display, RootWindow(display, visual->screen), 0, 0, 1, 1, 0,
                                   visual->depth, InputOutput, visual->visual,
                                   CWColormap | CWEventMask, &window_attributes);
    XFree(visual);
    if (!window) {
        fprintf(stderr, "opengl-draw: XCreateWindow: no window\n");
        XCloseDisplay(display);
        return 1;
    }
    /* the context has to name the configuration the window was made from, since the server
     * refuses a context whose visual the drawable does not carry */
    GLXContext context = glXCreateNewContext(display, configs[0], GLX_RGBA_TYPE, NULL, True);
    XFree(configs);
    if (!context) {
        fprintf(stderr, "opengl-draw: glXCreateNewContext: no context\n");
        XDestroyWindow(display, window);
        XCloseDisplay(display);
        return 1;
    }
    if (!glXMakeContextCurrent(display, window, window, context)) {
        fprintf(stderr, "opengl-draw: glXMakeContextCurrent: the context stayed unbound\n");
        glXDestroyContext(display, context);
        XDestroyWindow(display, window);
        XCloseDisplay(display);
        return 1;
    }
    GLint major = 0, minor = 0;
    glGetIntegerv(GL_MAJOR_VERSION, &major);
    glGetIntegerv(GL_MINOR_VERSION, &minor);
    const char *vendor = (const char *)glGetString(GL_VENDOR);
    const char *renderer = (const char *)glGetString(GL_RENDERER);
    const char *version = (const char *)glGetString(GL_VERSION);
    printf("opengl-draw vendor=\"%s\" renderer=\"%s\" version=\"%s\"\n", vendor ? vendor : "unknown",
           renderer ? renderer : "unknown", version ? version : "unknown");
    if (major < 3 || (major == 3 && minor < 3)) {
        fprintf(stderr, "opengl-draw: the context is below 3.3 core\n");
        glXMakeContextCurrent(display, None, None, NULL);
        glXDestroyContext(display, context);
        XDestroyWindow(display, window);
        XCloseDisplay(display);
        return 1;
    }

    GLuint texture = 0, framebuffer = 0;
    glGenTextures(1, &texture);
    glBindTexture(GL_TEXTURE_2D, texture);
    glTexStorage2D(GL_TEXTURE_2D, 1, GL_RGBA8, SIDE, SIDE);
    glGenFramebuffers(1, &framebuffer);
    glBindFramebuffer(GL_FRAMEBUFFER, framebuffer);
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, texture, 0);
    if (glCheckFramebufferStatus(GL_FRAMEBUFFER) != GL_FRAMEBUFFER_COMPLETE) {
        fprintf(stderr, "opengl-draw: the framebuffer is incomplete\n");
        glXMakeContextCurrent(display, None, None, NULL);
        glXDestroyContext(display, context);
        XDestroyWindow(display, window);
        XCloseDisplay(display);
        return 1;
    }
    GLuint vertex = compile(GL_VERTEX_SHADER, vertex_source);
    GLuint fragment = compile(GL_FRAGMENT_SHADER, fragment_source);
    if (!vertex || !fragment) {
        glXMakeContextCurrent(display, None, None, NULL);
        glXDestroyContext(display, context);
        XDestroyWindow(display, window);
        XCloseDisplay(display);
        return 1;
    }
    GLuint program = glCreateProgram();
    glAttachShader(program, vertex);
    glAttachShader(program, fragment);
    glLinkProgram(program);
    GLint linked = GL_FALSE;
    glGetProgramiv(program, GL_LINK_STATUS, &linked);
    if (!linked) {
        char log[2048];
        glGetProgramInfoLog(program, sizeof log, NULL, log);
        fprintf(stderr, "opengl-draw: the program did not link: %s\n", log);
        glXMakeContextCurrent(display, None, None, NULL);
        glXDestroyContext(display, context);
        XDestroyWindow(display, window);
        XCloseDisplay(display);
        return 1;
    }
    glUseProgram(program);
    /* dithering is on by default and moves a gradient by a step or two, which the readback
     * tolerance already allows, so it is turned off rather than compensated for */
    glDisable(GL_DITHER);
    /* a core profile needs a bound vertex array even when the shader reads gl_VertexID */
    GLuint array = 0;
    glGenVertexArrays(1, &array);
    glBindVertexArray(array);
    glViewport(0, 0, SIDE, SIDE);
    glClearColor(0.0f, 0.0f, 1.0f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);
    glDrawArrays(GL_TRIANGLES, 0, 3);
    glFinish();

    unsigned char pixels[SIDE * SIDE * 4];
    glPixelStorei(GL_PACK_ALIGNMENT, 1);
    glReadPixels(0, 0, SIDE, SIDE, GL_RGBA, GL_UNSIGNED_BYTE, pixels);
    const GLenum error = glGetError();
    if (error != GL_NO_ERROR) {
        fprintf(stderr, "opengl-draw: glReadPixels: error 0x%x\n", error);
        glXMakeContextCurrent(display, None, None, NULL);
        glXDestroyContext(display, context);
        XDestroyWindow(display, window);
        XCloseDisplay(display);
        return 1;
    }
    /* glReadPixels returns the bottom row first, so the gradient rises as the index falls.
     * the triangle covers the whole target, so the clear colour surviving anywhere would mean
     * the draw did not reach the corners: its blue channel is the witness */
    unsigned char *bottom_left = pixels;
    unsigned char *top_right = pixels + (size_t)(SIDE * SIDE - 1) * 4;
    unsigned char *centre = pixels + ((SIDE / 2) * SIDE + SIDE / 2) * 4;
    int failures = 0;
    if (!near(bottom_left[0], 0.0f) || !near(bottom_left[1], 0.0f) || bottom_left[2] != 0)
        failures++;
    if (!near(top_right[0], 1.0f) || !near(top_right[1], 1.0f) || top_right[2] != 0)
        failures++;
    if (!near(centre[0], 0.5f) || !near(centre[1], 0.5f) || centre[2] != 0)
        failures++;
    printf("opengl-draw pixels=%dx%d corner=%u,%u,%u centre=%u,%u,%u far=%u,%u,%u failures=%d\n",
           SIDE, SIDE, bottom_left[0], bottom_left[1], bottom_left[2], centre[0], centre[1],
           centre[2], top_right[0], top_right[1], top_right[2], failures);
    glXMakeContextCurrent(display, None, None, NULL);
    glDeleteVertexArrays(1, &array);
    glDeleteProgram(program);
    glDeleteShader(vertex);
    glDeleteShader(fragment);
    glDeleteFramebuffers(1, &framebuffer);
    glDeleteTextures(1, &texture);
    glXDestroyContext(display, context);
    XDestroyWindow(display, window);
    XCloseDisplay(display);
    return failures ? 1 : 0;
}
