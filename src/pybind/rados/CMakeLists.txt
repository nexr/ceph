distutils_add_cython_module(cython${PYTHON_VERSION}_rados
  rados${PYTHON_VERSION}
  ${CMAKE_CURRENT_SOURCE_DIR}/rados.pyx)
add_dependencies(cython${PYTHON_VERSION}_rados rados)
distutils_install_cython_module(cython${PYTHON_VERSION}_rados)
