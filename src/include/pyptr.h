/**
 * @file pyptr.h
 * @author D810
 * @brief A smart pointer for Python objects, using Python's reference counting
 * @version 0.1
 * @date 2025-08-11
 *
 * @copyright Copyright (c) 2025
 *
 * =============================================================================
 *  D810::pyptr<T> - A C++ smart pointer for PyObject* and friends
 * =============================================================================
 *
 *  Motivation:
 *  -----------
 *  - When writing C++ code that interoperates with Python (e.g., via the Python C API,
 *    Cython, or SWIG), you must manually manage reference counts for PyObject*.
 *  - Forgetting to INCREF/DECREF leads to leaks or crashes.
 *  - std::shared_ptr cannot be used directly, because PyObject* has its own refcounting.
 *
 *  What is pyptr<T>?
 *  -----------------
 *  - A minimal, header-only smart pointer that wraps a PyObject* (or any Python C API object)
 *    and manages its reference count using Py_XINCREF/Py_XDECREF.
 *  - Semantics are similar to std::shared_ptr<T>, but the "sharedness" is always correct
 *    because Python itself tracks the refcount.
 *  - Copying a pyptr<T> increments the refcount; destruction decrements it.
 *  - Move semantics are supported (move leaves the source null).
 *  - Null pointers are handled safely (Py_XINCREF/DECREF are null-safe).
 *
 *  Why not use std::shared_ptr<PyObject>?
 *  --------------------------------------
 *  - std::shared_ptr would double-manage the lifetime, which is wrong for PyObject*.
 *  - pyptr<T> is a "shim" that delegates all ownership to Python's refcounting.
 *  - This avoids double-free, and is always correct even if the object is also owned by Python.
 *
 *  Usability:
 *  ----------
 *  - Use pyptr<PyObject> (or pyptr<PyListObject>, etc) as a drop-in replacement for raw PyObject*.
 *  - You can pass pyptr<T> to any C API expecting T* (implicit conversion).
 *  - Use .get() to get the raw pointer, or operator->/operator* for pointer-like access.
 *  - Use .reset(), .swap(), assignment, etc, as with std::shared_ptr.
 *  - Use .use_count() to get the current Python refcount (for debugging).
 *  - Use .unique() to check if this is the only reference (rarely useful in Python, but provided).
 *  - Use new_shared(f, args...) to construct a pyptr from a factory function returning a T*.
 *
 *  Example:
 *  --------
 *      pyptr<PyObject> obj(PyList_New(0)); // refcount=1
 *      {
 *          pyptr<PyObject> obj2 = obj;     // refcount=2
 *      }                                   // obj2 destroyed, refcount=1
 *      obj.reset();                        // refcount=0, Py_DECREF called
 *
 *  Caveats:
 *  --------
 *  - pyptr<T> does NOT manage Python's GIL. You must ensure the GIL is held when manipulating Python objects.
 *  - pyptr<T> is not thread-safe (but neither is Python's refcounting).
 *  - Do not use pyptr<T> for objects not managed by Python's refcounting.
 *  - pyptr<T> is not polymorphic: pyptr<PyObject> and pyptr<PyListObject> are unrelated types.
 *
 *  Advanced:
 *  ---------
 *  - The new_shared() helper allows you to wrap factory functions (e.g., PyList_New) in a type-safe way.
 *  - Comparison operators and swap are provided for convenience.
 *  - object_ptr is an alias for pyptr<PyObject>.
 *
 *  This header is self-contained and has no dependencies except Python.h and <utility>.
 */

#ifndef _D810_PYPTR_H
#define _D810_PYPTR_H

#include <Python.h>
#include <utility>

namespace D810
{

    /**
     * @brief Smart pointer for Python objects (PyObject* or similar).
     *
     * pyptr<T> manages the reference count of a Python object.
     * Copying increments the refcount, destruction decrements it.
     * Move semantics are supported.
     *
     * @tparam T The Python C API type (usually PyObject or a subclass).
     */
    template <typename T>
    struct pyptr
    {
        using element_type = T;

    public:
        /// Default constructor: null pointer.
        pyptr() noexcept : p_(nullptr)
        {
        }

        /// Construct from nullptr.
        pyptr(std::nullptr_t) noexcept : pyptr()
        {
        }

        /// Construct from a raw pointer, takes ownership (INCREF).
        explicit pyptr(element_type *p) : p_(p)
        {
            Py_XINCREF(p_);
        }

        /// Move constructor: transfers ownership, source is set to null.
        pyptr(pyptr &&r) noexcept : p_(r.p_)
        {
            r.p_ = nullptr;
        }

        /// Copy constructor: increments refcount.
        pyptr(pyptr const &r) noexcept : p_(r.p_)
        {
            Py_XINCREF(p_);
        }

        /// Destructor: decrements refcount.
        ~pyptr() noexcept
        {
            Py_XDECREF(p_);
        }

        /// Copy/move assignment: copy-and-swap idiom.
        pyptr &operator=(pyptr r) noexcept
        {
            swap(r);
            return *this;
        }

        /// Reset to null (decrements refcount if not null).
        void reset() noexcept
        {
            pyptr().swap(*this);
        }

        /// Reset to a new pointer (decrements old, increments new).
        void reset(element_type *p)
        {
            pyptr(p).swap(*this);
        }

        /// Swap with another pyptr.
        void swap(pyptr &r) noexcept
        {
            std::swap(p_, r.p_);
        }

        /// Implicit conversion to raw pointer.
        operator element_type *() const noexcept
        {
            return get();
        }

        /// Get the raw pointer.
        element_type *get() const noexcept
        {
            return p_;
        }

        /// Dereference operator.
        element_type &operator*() const noexcept
        {
            return *get();
        }

        /// Member access operator.
        element_type *operator->() const noexcept
        {
            return get();
        }

        /// Get the current Python refcount (for debugging).
        Py_ssize_t use_count() const noexcept
        {
            return Py_REFCNT(p_);
        }

        /// True if this is the only reference (rarely useful).
        bool unique() const noexcept
        {
            return use_count() == 1;
        }

        /// Boolean conversion: true if not null.
        explicit operator bool() const noexcept
        {
            return get() != nullptr;
        }

    private:
        element_type *p_; ///< The managed pointer.
    };

    namespace detail
    {
        /**
         * @brief Helper to deduce the return type of new_shared().
         *
         * Given a function F and arguments Args..., deduces the type returned by F(Args...),
         * removes pointer, and wraps in pyptr<>.
         */
        template <typename F, typename... Args>
        struct shared_result_of
        {
            using type = pyptr<
                typename std::remove_pointer<
                    typename std::result_of<F(Args...)>::type>::type>;
        };

    }

    /**
     * @brief Helper to construct a pyptr from a factory function.
     *
     * Example: auto p = new_shared(PyList_New, 10);
     *
     * @tparam F Factory function type.
     * @tparam Args Argument types.
     * @param f The factory function.
     * @param args Arguments to pass to f.
     * @return pyptr<T> where T is deduced from f(args...).
     */
    template <typename F, typename... Args>
    auto new_shared(F f, Args... args)
        -> typename detail::shared_result_of<F, Args...>::type
    {
        using P = typename detail::shared_result_of<F, Args...>::type;

        return P(f(args...));
    }

    // Comparison operators for pyptr<T>
    template <typename T, typename U>
    inline bool operator==(pyptr<T> const &x, pyptr<U> const &y) noexcept
    {
        return x.get() == y.get();
    }

    template <typename T, typename U>
    inline bool operator!=(pyptr<T> const &x, pyptr<U> const &y) noexcept
    {
        return !(x == y);
    }

    template <typename T>
    inline bool operator==(std::nullptr_t, pyptr<T> const &x) noexcept
    {
        return !x;
    }

    template <typename T>
    inline bool operator==(pyptr<T> const &x, std::nullptr_t) noexcept
    {
        return !x;
    }

    template <typename T>
    inline bool operator!=(std::nullptr_t, pyptr<T> const &x) noexcept
    {
        return bool(x);
    }

    template <typename T>
    inline bool operator!=(pyptr<T> const &x, std::nullptr_t) noexcept
    {
        return bool(x);
    }

    /// Swap two pyptr<T> instances.
    template <typename T>
    inline void swap(pyptr<T> &x, pyptr<T> &y) noexcept
    {
        x.swap(y);
    }

    /// Alias for pyptr<PyObject>
    using object_ptr = pyptr<PyObject>;

}

#endif