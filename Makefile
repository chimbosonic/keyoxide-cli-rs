bin:=cargo run --
bin_args:=--pretty

test_dir:="__tests__"
test_expected_ouputs_dir:="$(test_dir)/expected_outputs"


ietf_sample_key_file:="$(test_dir)/data/IETF_SAMPLE_PUBLIC_KEY_WITH_NOTATIONS.asc"

test_doip_key_file:="$(test_dir)/data/TEST_DOIP_PUBLIC_KEY.asc"
test_doip_fingerprint:="3637202523E7C1309AB79E99EF2DC5827B445F4B"
test_doip_email_address:="test@doip.rocks"

alexis_lowe_key_file="$(test_dir)/data/ALEXIS_LOWE_PUBLIC_KEY.asc"
alexis_lowe_fingerprint:="AC48BC1F029B6188D97E2D807C855DB4466DF0C6"
alexis_lowe_email_address:="alexis.lowe@chimbosonic.com"


temp_ouput_file:=$(shell mktemp)

#Test all tests
test: test-file-loading test-hkp test-wkd

#Test all file loading tests
test-file-loading: test-ietf-sample-file test-test-doip-file test-alexis-lowe-file

#Test loading ietf sample key file
test-ietf-sample-file:
	$(bin) -i $(ietf_sample_key_file) $(bin_args) > $(temp_ouput_file) && jd $(test_expected_ouputs_dir)/ietf_sample.json $(temp_ouput_file)
#Test loading test doip's key file
test-test-doip-file:
	$(bin) -i $(test_doip_key_file) $(bin_args) > $(temp_ouput_file) && jd $(test_expected_ouputs_dir)/test_doip.json $(temp_ouput_file)
#Test loading Alexis Lowe's key file
test-alexis-lowe-file:
	$(bin) -i $(alexis_lowe_key_file) $(bin_args) > $(temp_ouput_file) && jd $(test_expected_ouputs_dir)/alexis_lowe.json $(temp_ouput_file)

#Test all hkp tests
test-hkp: test-hkp-test-doip test-hkp-alexis-lowe

#Test all hkp tests for test doip's key 
test-hkp-test-doip: test-hkp-test-doip-fingerprint test-hkp-test-doip-email-address

#Test hkp via fingerprint for test doip's key 
test-hkp-test-doip-fingerprint:
	$(bin) -f hkp:$(test_doip_fingerprint) $(bin_args) > $(temp_ouput_file) && jd $(test_expected_ouputs_dir)/test_doip.json $(temp_ouput_file)
#Test hkp via email-address for test doip's key 
test-hkp-test-doip-email-address:
	$(bin) -f hkp:$(test_doip_email_address) $(bin_args) > $(temp_ouput_file) && jd $(test_expected_ouputs_dir)/test_doip.json $(temp_ouput_file)

#Test all hkp tests for Alexis Lowe's key 
test-hkp-alexis-lowe: test-hkp-alexis-lowe-fingerprint test-hkp-alexis-lowe-email-address

#Test hkp via fingerprint for Alexis Lowe's key 
test-hkp-alexis-lowe-fingerprint:
	$(bin) -f hkp:$(alexis_lowe_fingerprint) $(bin_args) > $(temp_ouput_file) && jd $(test_expected_ouputs_dir)/alexis_lowe.json $(temp_ouput_file)

#Test hkp via email-address for Alexis Lowe's key 
test-hkp-alexis-lowe-email-address:
	$(bin) -f hkp:$(alexis_lowe_email_address) $(bin_args) > $(temp_ouput_file) && jd $(test_expected_ouputs_dir)/alexis_lowe.json $(temp_ouput_file)

#Test all wkd tests
test-wkd: test-wkd-alexis-lowe test-wkd-test-doip

#Test wkd for test doip's key 
test-wkd-alexis-lowe:
	$(bin) -f wkd:$(alexis_lowe_email_address) $(bin_args) > $(temp_ouput_file) && jd $(test_expected_ouputs_dir)/alexis_lowe.json $(temp_ouput_file)

#Test wkd for test doip's key 
test-wkd-test-doip:
	$(bin) -f wkd:$(test_doip_email_address) $(bin_args) > $(temp_ouput_file) && jd $(test_expected_ouputs_dir)/test_doip.json $(temp_ouput_file)

#Update test ouput data for all keys
update-test-data: update-alexis-lowe-data update-test-doip-data update-ietf-sample-data

#Update test ouput data for Alexis Lowe's key 
update-alexis-lowe-data:
	$(bin) -i $(alexis_lowe_key_file) $(bin_args) > $(test_expected_ouputs_dir)/alexis_lowe.json

#Update test ouput data for test doip's key 
update-test-doip-data:
	$(bin) -i $(test_doip_key_file) $(bin_args) > $(test_expected_ouputs_dir)/test_doip.json

#Update test ouput data for ietf sample key
update-ietf-sample-data:
	$(bin) -i $(ietf_sample_key_file) $(bin_args) > $(test_expected_ouputs_dir)/ietf_sample.json