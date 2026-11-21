import time
import urllib.request
import docker
from pathlib import Path

client = docker.from_env()

BASE_DIR = Path(__file__).resolve().parent.parent

apps = {
    "cmd": 8081,
    "spel": 8082,
    "sql": 8083
}

for app_name, port in apps.items():
    app_path = BASE_DIR / "vulnerable-app" / f"{app_name}-vuln-app"

    image, logs = client.images.build(
        path = str(app_path),
        tag = f"seccheck-{app_name}",
        rm = True
    )

    print("Docker 이미지 빌드 완료:", image.tags)

    container = client.containers.run(
        image = f"seccheck-{app_name}",
        name = f"seccheck-{app_name}-container",
        ports = {f"{port}/tcp": port},
        detach = True,
        mem_limit = "512m",
        nano_cpus = 1000000000
    )

    print("컨테이너 실행 완료:", container.name)

    url = f"http://localhost:{port}/actuator/health"

    for i in range(10):
        try: 
            response = urllib.request.urlopen(url, timeout=3)
            print("서버 상태:", response.read().decode())
            break
        except Exception:
            print("서버 시작 대기 중...")
            time.sleep(3)
    else:
        print("서버 정상 실행 확인 실패")
    
    container.stop()
    print("컨테이너 종료 완료:", container.name)

    container.remove()
    print("컨테이너 삭제 완료")
 