jni_ld_library="/usr/lib/jvm/jre/lib/amd64/server:/usr/lib/jvm/jre/lib/amd64:/usr/lib/jvm/jre/lib:/usr/lib/jvm/jre/lib/server"

if [ "x" == "x${LD_LIBRARY_PATH}" ]; then
  export LD_LIBRARY_PATH=${jni_ld_library}
else
  export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${jni_ld_library}
fi
