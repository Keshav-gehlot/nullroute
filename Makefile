# NullRoute — common tasks. Run `make` for the list.
.PHONY: help lists extension test test-compiler test-extension android ios clean

help:
	@echo "make lists           Download filter lists and compile them for every platform"
	@echo "make extension       Build the Chrome extension (then Load unpacked: ./extension)"
	@echo "make test            Compiler tests + Chrome end-to-end tests"
	@echo "make android         Build the debug APK (needs Android SDK)"
	@echo "make ios             Generate the Xcode project (needs xcodegen)"

lists:
	cd compiler && python3 -m nullroute_compiler --out ../dist

extension: lists
	node extension/scripts/build.mjs

test-compiler:
	cd compiler && python3 -m pytest -q

test-extension: extension
	node --test extension/tests/shields.test.mjs
	python3 -m pytest extension/tests -q

test: test-compiler test-extension

android: lists
	cd android && ./gradlew :core:test :app:assembleDebug

ios: lists
	cd ios && xcodegen generate

clean:
	rm -rf dist extension/rulesets compiler/.cache android/build android/app/build android/core/build
