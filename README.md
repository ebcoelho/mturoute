# MTUROUTE

This is a fork of MTUROUTE from Eli Fulkerson (elifulkerson.com)

## macOS

A native macOS port (Apple Silicon and Intel) lives in [`macos/`](macos/). It needs no sudo.

```
cd macos
make
./mturoute -t 1.1.1.1
```

See [macos/README.md](macos/README.md) for details.

## Windows build

```
msbuild /t:rebuild mturoute.sln
```

## Alternative

```
docker run -it alpine
  / # apk add --no-cache iputils
  / # tracepath -n -p 80 google.com
```
