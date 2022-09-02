if(WITH_PYTHON2)
  set(PYTHON_VERSION "2")
elseif(WITH_PYTHON3)
  set(PYTHON_VERSION "3")
endif()

include(Distutils)

distutils_install_module(ceph)

# Required for running python-common inventory in a vstart environment
set(PYTHON_COMMON_VIRTUALENV ${CEPH_BUILD_VIRTUALENV}/python-common-virtualenv)

add_custom_command(
  OUTPUT ${PYTHON_COMMON_VIRTUALENV}/bin/python
  COMMAND ${CMAKE_SOURCE_DIR}/src/tools/setup-virtualenv.sh --python=${PYTHON_EXECUTABLE} ${PYTHON_COMMON_VIRTUALENV}
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/python-common
  COMMENT "python-common venv is being created")

add_custom_command(
  OUTPUT ${PYTHON_COMMON_VIRTUALENV}/bin/python-common
  DEPENDS ${PYTHON_COMMON_VIRTUALENV}/bin/python
  COMMAND . ${PYTHON_COMMON_VIRTUALENV}/bin/activate && ${PYTHON_COMMON_VIRTUALENV}/bin/python setup.py install && deactivate
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/python-common
  COMMENT "${CMAKE_SOURCE_DIR}/src/python-common")

add_custom_target(python${PY_BINDING_INFIX}-common-venv-setup
  DEPENDS ${PYTHON_COMMON_VIRTUALENV}/bin/python-common)

