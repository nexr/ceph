#define _XOPEN_SOURCE
#include <jni.h>
#include <iostream>
#include <string>
#include <unistd.h>
#include <time.h>
using namespace std;

class ranger_jni {
private:
  JavaVM *jvm;
  JNIEnv *jni_env;
  JavaVMInitArgs vm_args;
  jclass jcls;
  jobject jinst;

  jmethodID isAccessAllowed_mid;

public:
  ranger_jni(bool start_vm = false) {
    string java_class_path = ".:/usr/share/ceph/rgw/ranger/engine/nesRangerEngine-1.0-SNAPSHOT.jar";
    char class_path_opt_str[200];
    sprintf(class_path_opt_str, "%s=%s", "-Djava.class.path", java_class_path.c_str());

    char* jvm_locale_opt = (char*) "-Duser.language=en-US";

    JavaVMOption jvmopt[2];
    jvmopt[0].optionString = class_path_opt_str;
    jvmopt[1].optionString = jvm_locale_opt;

    JNI_GetDefaultJavaVMInitArgs(&vm_args);
    vm_args.version = JNI_VERSION_1_8;
    vm_args.nOptions = 2;
    vm_args.options = jvmopt;
    vm_args.ignoreUnrecognized = JNI_TRUE;

    if (start_vm) {
      start_jvm();
    }
  }

  ~ranger_jni() {
    if (jvm != NULL) {
      stop_jvm();
    }
  }

  int start_jvm() {
    long flag = JNI_CreateJavaVM(&jvm, (void**) &jni_env, &vm_args);
    if (flag == JNI_ERR) {
      jvm = NULL;

      cout << "Error creating VM. Exiting...\n";
      return 1;
    }

    jcls = jni_env->FindClass("com/nes/ranger/NesRangerEngine");
    if (jcls == NULL) {
      jvm = NULL;
      jni_env->ExceptionDescribe();
      jvm->DestroyJavaVM();

      cout << "Error find class. Exiting...\n";
      return 2;
    }

    jmethodID constructor = jni_env->GetMethodID(jcls, "<init>", "(Ljava/lang/String;)V");
    if (constructor == NULL) {
      jvm = NULL;
      jni_env->ExceptionDescribe();
      jvm->DestroyJavaVM();

      cout << "Error find constructor. Exiting...\n";
      return 3;
    }

    jstring appIdString = jni_env->NewStringUTF("jni_proto");

    jinst = jni_env->NewObject(jcls, constructor, appIdString);
    if (jinst == NULL) {
      jvm = NULL;
      jni_env->ExceptionDescribe();
      jvm->DestroyJavaVM();

      cout << "Error construct NesRangerEngine obj. Exiting...\n";
      return 4;
    }

    isAccessAllowed_mid = jni_env->GetMethodID(jcls, "isAccessAllowed", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z");
    if (isAccessAllowed_mid == NULL) {
      cout << "Error find isAccessAllowed(string, string, string, string). Exiting...\n";
      return 5;
    }

    return 0;
  }

  void stop_jvm() {
    jni_env->DeleteLocalRef(jinst);
    jvm->DestroyJavaVM();

    jvm = NULL;
    jni_env = NULL;
    isAccessAllowed_mid = NULL;
  }

  bool is_access_allowed(string service, string url, string path, string access_type, string user, string group) {
    jboolean is_allowed = jni_env->CallBooleanMethod(jinst, isAccessAllowed_mid,
                                                     jni_env->NewStringUTF(service.c_str()),
                                                     jni_env->NewStringUTF(url.c_str()),
                                                     jni_env->NewStringUTF(path.c_str()),
                                                     jni_env->NewStringUTF(access_type.c_str()),
                                                     jni_env->NewStringUTF(user.c_str()),
                                                     jni_env->NewStringUTF(group.c_str()));
    if (jni_env->ExceptionCheck()) {
      jni_env->ExceptionDescribe();
      jni_env->ExceptionClear();
    }

    string result_str;
    if (is_allowed) {
      result_str = "allowed";
    }
    else {
      result_str = "denied";
    }

    string result_msg = "The '" + user + "' " + access_type + " request for '" + path + "' is " + result_str;

    cout << result_msg << endl;

    return is_allowed;
  }
};


int main(int argc, const char **argv)
{

  string s = "Thu, 14 Apr 2022 02:26:21 +0000";
  string format = "%a, %d %b %Y %H:%M:%S %z";

  struct tm t;

  if (strptime(s.c_str(), format.c_str(), &t) == NULL) {
    cout << "strptime error before jvm creation" << endl;
  }

  char result1[1024];
  strftime(result1, 1024, format.c_str(), &t);
  cout << "data check: " << result1 << endl;


  char *(*func_ptr)(const char *, const char *, struct tm *) = strptime;
  cout << "address of strptime() before jvm creation: " << (void*) func_ptr << endl;

  struct tm t2;
  char* s2 = (char*) "Thu, 14 Apr 2022 02:26:21 +0000";
  cout << s2 << endl;
  s2 = strptime(s2, "%a, ", &t2);
  if (s2 == NULL) {
    cout << "strptime error before jvm creation(step 1)" << endl;
    return 1;
  }
  else {
    cout << s2 << endl;
  }

  s2 = strptime(s2, "%d ", &t2);
  if (s2 == NULL) {
    cout << "strptime error before jvm creation(step 2)" << endl;
    return 2;
  }
  else {
    cout << s2 << endl;
  }

  s2 = strptime(s2, "%b ", &t2);
  if (s2 == NULL) {
    cout << "strptime error before jvm creation(step 3)" << endl;
    return 3;
  }
  else {
    cout << s2 << endl;
  }

  s2 = strptime(s2, "%Y ", &t2);
  if (s2 == NULL) {
    cout << "strptime error before jvm creation(step 4)" << endl;
    return 4;
  }
  else {
    cout << s2 << endl;
  }

  s2 = strptime(s2, "%H:", &t2);
  if (s2 == NULL) {
    cout << "strptime error before jvm creation(step 5)" << endl;
    return 5;
  }
  else {
    cout << s2 << endl;
  }

  s2 = strptime(s2, "%M:", &t2);
  if (s2 == NULL) {
    cout << "strptime error before jvm creation(step 6)" << endl;
    return 6;
  }
  else {
    cout << s2 << endl;
  }

  s2 = strptime(s2, "%S ", &t2);
  if (s2 == NULL) {
    cout << "strptime error before jvm creation(step 7)" << endl;
    return 7;
  }
  else {
    cout << s2 << endl;
  }

  s2 = strptime(s2, "%z", &t2);
  if (s2 == NULL) {
    cout << "strptime error before jvm creation(step 8)" << endl;
    return 8;
  }
  else {
    cout << s2 << endl;
  }

  ranger_jni* rjni = new ranger_jni(true);
  //std::setlocale(LC_ALL, "en_US.UTF-8");

//  rjni->is_access_allowed("datalake1", "http://192.168.80.59:6080", "/dl1-bucket2/abc", "read", "datalake1", "nes");
//  rjni->is_access_allowed("datalake1", "http://192.168.80.59:6080", "/dl1-bucket1/obj1", "write", "datalake1", "nes");
//  rjni->is_access_allowed("datalake1", "http://192.168.80.59:6080", "/dl1-bucket1/obj1", "write", "datalake2", "nes");
//  rjni->is_access_allowed("datalake1", "http://192.168.80.59:6080", "/dl1-bucket1/obj1", "read", "clarke", "nes");
//  rjni->is_access_allowed("datalake2", "http://192.168.80.60:6080", "/dl2-bucket1/obj1", "read", "clarke", "nes");
//  rjni->is_access_allowed("datalake2", "http://192.168.80.60:6080", "/dl2-bucket2/abc.tar", "write", "datalake_other", "nes");
//  rjni->is_access_allowed("datalake_other", "http://192.168.80.61:6080", "/dlo-bucket1/obj1", "read", "clarke", "my_nes");
//  rjni->is_access_allowed("datalake_other", "http://192.168.80.61:6080", "/dlo-bucket1/obj1", "read", "datalake1", "my_nes");

//  cout << "<< rfc850 case >>" << endl;
//  string rfc850_format = "%A, %d-%b-%y %H:%M:%S %Z";
//  char* rfc850_cstr = (char*) "Tuesday, 28-Jan-20 23:22:37 GMT";
//
//  {
//    struct tm instance;
//    struct tm *t = &instance;
//
//    string str(rfc850_cstr);
//
//    size_t delim_pos = str.find(',');
//    if (delim_pos == string::npos) { return 0; }
//
//    string front_str = str.substr(0, delim_pos);
//    string back_str  = str.substr(delim_pos+1);
//
//    cout << "split " << str << ": " << front_str << " / " << back_str << endl;
//
//    if (strptime(front_str.c_str(), "%A", t) == NULL) { return 0; }
//
//    char* remain = strptime(back_str.c_str(), "%d-%b-%y %H:%M:%S ", t);
//    cout << "remains: " << remain << endl;
//
//    strptime(remain, "%Z", t);
//
//    char result[1024];
//    strftime(result, 1024, rfc850_format.c_str(), t);
//    cout << "data check: " << result << endl;
//  }
//
//  cout << "<< asctime case >>" << endl;
//  string asctime_format = "%a %b %d %H:%M:%S %Y";
//  char* asctime_cstr = (char*) "Tue Jan 28 23:22:37 2020";
//
//  {
//    struct tm instance;
//    struct tm *t = &instance;
//
//    string str(asctime_cstr);
//
//    size_t delim_pos = str.find(' ');
//    if (delim_pos == string::npos) { return 0; }
//
//    string front_str = str.substr(0, delim_pos);
//    string back_str  = str.substr(delim_pos+1);
//
//    cout << "split " << str << ": " << front_str << " / " << back_str << endl;
//
//    if (strptime(front_str.c_str(), "%a", t) == NULL) { return 0; }
//
//    char* remain = strptime(back_str.c_str(), "%b %d %H:%M:%S %Y", t);
//    cout << "remains: " << remain << endl;
//
//    char result[1024];
//    strftime(result, 1024, rfc850_format.c_str(), t);
//    cout << "data check: " << result << endl;
//  }

  cout << "<< rfc1123 case >>" << endl;
  string rfc1123_format = "%a, %d %b %Y %H:%M:%S %Z";
  char* rfc1123_cstr = (char*) "Tue, 28 Jan 2020 23:22:37 GMT";

  {
    struct tm instance;
    struct tm *t = &instance;

    string str(rfc1123_cstr);

    size_t delim_pos = str.find(',');
    if (delim_pos == string::npos) { return 0; }

    string front_str = str.substr(0, delim_pos);
    string back_str  = str.substr(delim_pos+1);

    cout << "split " << str << ": " << front_str << " / " << back_str << endl;

    if (strptime(front_str.c_str(), "%a", t) == NULL) { return 0; }

    char* remain = strptime(back_str.c_str(), "%d %b %Y %H:%M:%S ", t);
    cout << "remains: " << remain << endl;

    strptime(remain, "%Z", t);

    char result[1024];
    strftime(result, 1024, rfc1123_format.c_str(), t);
    cout << "data check: " << result << endl;
  }

  cout << "<< rfc1123_alt case >>" << endl;
  string rfc1123_alt_format = "%a, %d %b %Y %H:%M:%S %z";
  char* rfc1123_alt_cstr = (char*) "Tue, 28 Jan 2020 16:22:37 -0700";

  {
    struct tm instance;
    struct tm *t = &instance;

    string str(rfc1123_alt_cstr);

    size_t delim_pos = str.find(',');
    if (delim_pos == string::npos) { return 0; }

    string front_str = str.substr(0, delim_pos);
    string back_str  = str.substr(delim_pos+1);

    cout << "split " << str << ": " << front_str << " / " << back_str << endl;

    if (strptime(front_str.c_str(), "%a", t) == NULL) { return 0; }

    char* remain = strptime(back_str.c_str(), "%d %b %Y %H:%M:%S %z", t);
    cout << "remains: " << remain << endl;

    char result[1024];
    strftime(result, 1024, rfc1123_alt_format.c_str(), t);
    cout << "data check: " << result << endl;
  }



//  string s3 = "Thu, 14 Apr 2022 02:26:21 +0000";
//  string format3 = "%a, %d %b %Y %H:%M:%S %z";
//
//  struct tm t3;
//
//  if (strptime(s3.c_str(), format3.c_str(), &t3) == NULL) {
//    cout << "strptime error after jvm creation" << endl;
//  }
//
//  char *(*func_ptr2)(const char *, const char *, struct tm *) = strptime;
//  cout << "address of strptime() after jvm creation: " << (void*) func_ptr2 << endl;
//
//
//  struct tm t4;
//  //char* s4 = (char*) "Thu, 14 Apr 2022 02:26:21 +0000";
//  char* s4 = (char*) "Thu, 14 Apr 2022 02:26:21 +0000";
//  cout << s4 << endl;
//
//  s4 = strptime(s4, "%a", &t4);
//  if (s4 == NULL) {
//    cout << "strptime error after jvm creation(step 1)" << endl;
//    return 1;
//  }
//  else {
//    cout << s4 << endl;
//    cout << "time wday: " << t4.tm_wday << endl;
//  }
//
//  s4 = strptime(s4, "%d ", &t4);
//  if (s4 == NULL) {
//    cout << "strptime error after jvm creation(step 2)" << endl;
//    return 2;
//  }
//  else {
//    cout << s4 << endl;
//  }
//
//  s4 = strptime(s4, "%b ", &t4);
//  if (s4 == NULL) {
//    cout << "strptime error after jvm creation(step 3)" << endl;
//    return 3;
//  }
//  else {
//    cout << s4 << endl;
//  }
//
//  s4 = strptime(s4, "%Y ", &t4);
//  if (s4 == NULL) {
//    cout << "strptime error after jvm creation(step 4)" << endl;
//    return 4;
//  }
//  else {
//    cout << s4 << endl;
//  }
//
//  s4 = strptime(s4, "%H:", &t4);
//  if (s4 == NULL) {
//    cout << "strptime error after jvm creation(step 5)" << endl;
//    return 5;
//  }
//  else {
//    cout << s4 << endl;
//  }
//
//  s4 = strptime(s4, "%M:", &t4);
//  if (s4 == NULL) {
//    cout << "strptime error after jvm creation(step 6)" << endl;
//    return 6;
//  }
//  else {
//    cout << s4 << endl;
//  }
//
//  s4 = strptime(s4, "%S ", &t4);
//  if (s4 == NULL) {
//    cout << "strptime error after jvm creation(step 7)" << endl;
//    return 7;
//  }
//  else {
//    cout << s4 << endl;
//  }
//
//  s4 = strptime(s4, "%z", &t4);
//  if (s4 == NULL) {
//    cout << "strptime error after jvm creation(step 7)" << endl;
//    return 7;
//  }
//  else {
//    cout << s4 << endl;
//  }


//  s3 = strptime(s3, "%b ", &t3);
//  cout << s3 << endl;
//  s3 = strptime(s3, "%Y ", &t3);
//  cout << s3 << endl;
//  s3 = strptime(s3, "%H:", &t3);
//  cout << s3 << endl;
//  s3 = strptime(s3, "%M:", &t3);
//  cout << s3 << endl;
//  s3 = strptime(s3, "%S: ", &t3);
//  cout << s3 << endl;
//  s3 = strptime(s3, "%z", &t3);
//  cout << s3 << endl;


  return 0;
}

