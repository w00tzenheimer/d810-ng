#ifndef EXPORT_H
#define EXPORT_H

#ifdef _WIN32
    #define EXPORT __declspec(dllexport)
#else
    #define EXPORT __attribute__((visibility("default")))
#endif

#endif /* EXPORT_H */
