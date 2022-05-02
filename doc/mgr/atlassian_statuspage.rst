Atlassian_statuspage module
===========================

개요
----

ceph-mgr의 모듈. nautilus version의 ceph을 기준으로 개발.

동작 방식
---------

ceph의 상태를 체크하고 연동된 [atlassian statuspage](https://www.atlassian.com/ko/software/statuspage)에 상태를 알려준다.

ceph의 상태는 다음과 같이 statuspage의 component 상태로 전환된다.

- HEALTH_OK -> Operational
- HEALTH_WARN -> Degraded Performance
- HEALTH_ERR -> Partial Outage
- HEALTH_DOWN -> Major Outage

설치
----

모든 ceph-mgr 노드에서 다음과 같은 명령을 통해 atlassian_statuspage 모듈의 설치 여부를 확인할 수 있다. ::

  $ systemctl restart ceph-mgr@* # 모든 ceph-mgr 노드에서 수행
  $ ceph mgr module ls |grep atlas
              "name": "atlassian_statuspage",

설정
----

atlassian_statuspage 모듈의 email 모드를 사용하기 위해서는 활용 가능한 smtp 서버가 필요하다. ::

  $ ceph config set mgr mgr/atlassian_statuspage/interval <check_interval seconds>

  $ ceph config set mgr mgr/atlassian_statuspage/page_id <page_id of statuspage>
  $ ceph config set mgr mgr/atlassian_statuspage/component_id <component_id of statuspage>

  $ ceph config set mgr mgr/atlassian_statuspage/automation_mode [email|rest]

  # if automation_mode == rest, RestAPI config
  $ ceph config set mgr mgr/atlassian_statuspage/rest_token <auth token for statuspage>
  $ ceph config set mgr mgr/atlassian_statuspage/rest_url <endpoint of target statuspage>

  # if automation_mode == email, smtp config
  $ ceph config set mgr mgr/atlassian_statuspage/smtp_host <smtp host ip>
  $ ceph config set mgr mgr/atlassian_statuspage/smtp_port <smtp port>
  $ ceph config set mgr mgr/atlassian_statuspage/smtp_ssl <true|false>
  $ ceph config set mgr mgr/atlassian_statuspage/smtp_user <user to authenticate as>
  $ ceph config set mgr mgr/atlassian_statuspage/smtp_password <password to authenticate with>
  $ ceph config set mgr mgr/atlassian_statuspage/smtp_sender <envelope sender>

  # enable 'atlassian_statuspage' module
  $ ceph mgr module enable atlassian_statuspage

