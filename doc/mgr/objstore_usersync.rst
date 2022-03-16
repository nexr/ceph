# objstore_usersync

## 개요
ceph-mgr의 모듈. nautilus version의 ceph을 기준으로 개발.
nes 1.1.x 버전부터 사용 가능.

## 동작 방식
ceph 오브젝트 스토리지의 사용자 목록을 조회하여 상황에 맞게 대상 시스템의 사용자를 조작하여
두 시스템의 사용자 목록을 동기화 한다.

현재 지원하는 사용자 동기화가 가능한 대상 시스템은 다음과 같다.
- ranger

## 설치
모든 ceph-mgr 다음과 같은 명령을 통해 objstore_usersync의 설치 여부를 확인할 수 있다.
```bash
$ ceph mgr module ls |grep objstore_usersync
            "name": "objstore_usersync",
```

## 설정

```bash
$ ceph config set mgr mgr/objstore_usersync/interval <synchronize_interval seconds>

$ ceph config set mgr mgr/objstore_usersync/sync_target <target to synchronize use>
$ ceph config set mgr mgr/objstore_usersync/sync_tenant <tenant name for nes>
$ ceph config set mgr mgr/objstore_usersync/allow_user_remove [true|false]
$ ceph config set mgr mgr/objstore_usersync/endpoint_map_update_cycle <cycles to update>

## if 'ranger' in sync_target, ranger usersync config

# ranger connection config
$ ceph config set mgr mgr/objstore_usersync/ranger_rest_url <ranger url> # ex) http[s]://x.x.x.x:yy/service
$ ceph config set mgr mgr/objstore_usersync/ranger_rest_admin_user <ranger admin user name>
## choose one of bellow two password config.
$ ceph config set mgr mgr/objstore_usersync/ranger_rest_admin_password <ranger admin password>
$ ceph config set mgr mgr/objstore_usersync/ranger_rest_admin_password_path <path to file containing password>

# ranger action config
$ ceph config set mgr mgr/objstore_usersync/ranger_user_initial_password <default password for newly created user>
$ ceph config set mgr mgr/objstore_usersync/ranger_service_initial_endpoint <rgw endpoint for newly created S3 service>
$ ceph config set mgr mgr/objstore_usersync/ranger_user_hard_remove [true|false]

## enable 'objstore_usersync' module
$ ceph mgr module enable objstore_usersync
```

