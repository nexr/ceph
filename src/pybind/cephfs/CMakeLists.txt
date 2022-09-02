distutils_add_cython_module(cython${PYTHON_VERSION}_cephfs
  cephfs${PYTHON_VERSION}
  ${CMAKE_CURRENT_SOURCE_DIR}/cephfs.pyx)
add_dependencies(cython${PYTHON_VERSION}_cephfs cephfs)
distutils_install_cython_module(cython${PYTHON_VERSION}_cephfs)
