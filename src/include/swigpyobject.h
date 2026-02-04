#ifndef _D810_SWIGPYOBJECT_H
#define _D810_SWIGPYOBJECT_H

#include <Python.h>

// @fmt: off
// clang-format off
typedef struct
{
  PyObject_HEAD  // PyObject ob_base
  void *ptr;     // This is the pointer to the actual C instance
  void *ty;      // swig_type_info originally, but shouldn't matter
  int own;
  PyObject *next;
} SwigPyObject;
// clang-format on
// @fmt: on

template <typename T>
T swigtocpp(PyObject *obj)
{
  // unwraps python object to get the cpp pointer
  // from the swig bindings
  auto swigpointer = reinterpret_cast<SwigPyObject *>(obj);
  auto objpointervoid = swigpointer->ptr;
  auto objpointer = reinterpret_cast<T>(objpointervoid);
  return objpointer;
}

#endif