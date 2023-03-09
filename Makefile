bin:=cargo run --
bin_args:=--pretty

test_dir:="__tests__"
test_expected_ouputs_dir:="$(test_dir)/expected_outputs"


test_key_file:="$(test_dir)/data/IETF_SAMPLE_PUBLIC_KEY_WITH_NOTATIONS.asc"
test_key_fingerprint:="3637202523E7C1309AB79E99EF2DC5827B445F4B"
test_key_email_address:="test@doip.rocks"

temp_test_file:=$(shell mktemp --suffix .json)


test-all: test-asc-file test-wkd test-hkp

test-asc-file:
	$(bin) -i $(test_key_file) $(bin_args) > $(temp_test_file) && jd $(test_expected_ouputs_dir)/asc_file.json $(temp_test_file)



test-hkp: test-hkp-fingerprint test-hkp-email-address

test-hkp-fingerprint:
	$(bin) -f hkp:$(test_key_fingerprint) $(bin_args) > $(temp_test_file) && jd $(test_expected_ouputs_dir)/hkp.json $(temp_test_file)

test-hkp-email-address:
	$(bin) -f hkp:$(test_key_email_address) $(bin_args) > $(temp_test_file) && jd $(test_expected_ouputs_dir)/hkp.json $(temp_test_file)



test-wkd:
	$(bin) -f wkd:$(test_key_email_address) $(bin_args) > $(temp_test_file) && jd $(test_expected_ouputs_dir)/wkd.json $(temp_test_file)
