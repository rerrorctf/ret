CGO_ENABLED=0 go build -buildmode=pie -ldflags "-s -w -X 'main.COMMIT=`git rev-parse --short HEAD`' -extldflags '-static'" -gcflags "all=-trimpath=$GOPATH"
