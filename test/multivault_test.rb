
require 'minitest/autorun'
require_relative '../lib/multivault.rb'

class TestMultiVault < Minitest::Test

  # to be able to use :let to setup a state:
  extend Minitest::Spec::DSL

  # do test sequentially in programming order
  i_suck_and_my_tests_are_order_dependent!

  # test-wide constants
  # key locations
  let( :userkeydir_u1 ) { '.mvtest_u1' }
  let( :userkeydir_u2 ) { '.mvtest_u2' }
  # test user names
  let( :name_u1 ) { 'gonzo' }
  let( :name_u2 ) { 'kermit' }
  # data for test writes
  let( :vault_data ) { 'data written to vault' }
  # test vault file
  let( :vault_file ) { File.join( ENV['HOME'], 'mv_test.vault' ) }
  # access request file
  let( :request_file ) { File.join( ENV['HOME'], 'mv_test.access_request' ) }
  
  def test_aaa_create_keys
  
 	# create test key for user 1
	MVAULT.delete_key( userkeydir: userkeydir_u1 ) if Dir.exists?( File.join( ENV['HOME'], userkeydir_u1 ) )
	MVAULT.create_key( username: name_u1, userkeydir: userkeydir_u1 )
    # test if they exists
    keydir = File.join( ENV['HOME'], userkeydir_u1 )
    keyfile = File.join( ENV['HOME'], userkeydir_u1, 'user_private_key' )
    userfile = File.join( ENV['HOME'], userkeydir_u1, 'user_info' )
    assert( Dir.exists?( keydir ), "No user key directory: #{ keydir }" )
    assert( File.exists?( keyfile ), "No user key file: #{ keyfile }" )
    assert( File.exists?( userfile ), "No user info file: #{ userfile }" )
	
	# create test key for user 2
	MVAULT.delete_key( userkeydir: userkeydir_u2 ) if Dir.exists?( File.join( ENV['HOME'], userkeydir_u2 ) )
	MVAULT.create_key( username: name_u2, userkeydir: userkeydir_u2 )  
    # test if they exists
    keydir = File.join( ENV['HOME'], userkeydir_u2 )
    keyfile = File.join( ENV['HOME'], userkeydir_u2, 'user_private_key' )
    userfile = File.join( ENV['HOME'], userkeydir_u2, 'user_info' )
    assert( Dir.exists?( keydir ), "No user key directory: #{ keydir }" )
    assert( File.exists?( keyfile ), "No user key file: #{ keyfile }" )
    assert( File.exists?( userfile ), "No user info file: #{ userfile }" )  

  end

  def test_create_read_write_save_vault
    # gonzo creates a vault, writes changes the data and writes it to disk
  
	vaultname = "mv_test.vault"
	test_vault = MultiVault.new( vaultname: vaultname, userkeydir: userkeydir_u1 )
	# test if the default data is in the vault
	assert_equal DEFAULT_DATA, test_vault.read_data
	
	# write some data and see if it is really there
	test_vault.write_data( vault_data )
	assert_equal vault_data, test_vault.read_data
	
	# save the vault to a file 
	test_vault.write_to_disk( filename: vault_file )
	assert( File.exists?( vault_file ), "Vault with filename: #{} not found" )
  end
  
  def test_cannot_overwrite_existing_key
    # an existing key cannot be overwritten
    assert_raises RuntimeError do
	  MVAULT.create_key( userkeydir: userkeydir_u1 )
	end
  end

  def test_load_and_access_vault
    # we now become kermit and load the vault
    test_vault = MultiVault.new( vaultfile: vault_file, userkeydir: userkeydir_u2 )
    
    # kermit cannot read the data:
    assert_raises NoMethodError do
	  data = test_vault.read_data
    end
    
    # kermit creates an access request for gonzo
    MVAULT.request_access( vault_file: vault_file, request_file: request_file, userkeydir: userkeydir_u2 )
    assert( File.exists?( request_file ), "Access request #{ request_file } does not exists" )
    
    # gonzo gives kermit read access to a new vault, and writes the vault to disk
    new_test_vault = MultiVault.new( vaultfile: vault_file, userkeydir: userkeydir_u1 )
    new_test_vault.add_user( request_file )
    new_test_vault.write_to_disk
    
    # now kermit re-loads the vault and should be able to read the data
    test_vault = MultiVault.new( vaultfile: vault_file, userkeydir: userkeydir_u2 )
    assert_equal vault_data, test_vault.read_data
    
  end
  
end
