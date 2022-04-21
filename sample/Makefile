version := 0.0.9
projectName := uggsec-sample
packageNameWindows := $(projectName)-windows-amd64-$(version).tar.gz

build_dir := output
build_dir_windows := output-windows

build: format configure build-windows copy

format:
	go fmt ./...


configure:
		mkdir -p $(build_dir)
		mkdir -p $(build_dir_windows)



build-windows:
		env GOOS=windows GOARCH=amd64 go build -o ./$(build_dir_windows)/$(projectName).exe -ldflags "-X main.version=$(version)"
		@cd ./$(build_dir_windows) && tar zcf ../$(build_dir)/$(packageNameWindows) . 

copy:
		cp ./$(build_dir_windows)/* /mnt/c/Users/rendi/Documents/source/uggsec/

clean:
		rm -rf $(build_dir)
		rm -rf $(build_dir_windows)		 

