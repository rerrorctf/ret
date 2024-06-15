go build -buildmode=pie -ldflags "-s -w -X 'main.COMMIT=`git rev-parse --short HEAD`'" -gcflags "all=-trimpath=$GOPATH"
