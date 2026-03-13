# KILL SWITCH — Emergency Shutdown

## Stop and remove EVERYTHING:
```bash
docker compose -f D:\Lionguard\sandbox\docker-compose.yml down -v --rmi all
```

## Just stop (keep data for review):
```bash
docker compose -f D:\Lionguard\sandbox\docker-compose.yml down
```

## Check what's running:
```bash
docker ps --filter name=lionguard
```

## Nuclear option (remove ALL Lionguard artifacts):
```bash
docker compose -f D:\Lionguard\sandbox\docker-compose.yml down -v --rmi all
docker network prune -f
docker volume prune -f
```
