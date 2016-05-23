# author: jeroen vriesman <jeroen.vriesman@root-it.biz>

# implementation of a multu-user access vault
# access is based on "having the right private key", together with a username
# two types of users: reader and owners
# readers can read the vault
# owners can write the vault (that includes adding, deleting, promoting and demoting users)
# new users need to make a request to an owner to gain access to the vault (the request is a signature of the validation key + public key)

# private keys have length 4096
# a signature is a private key encrypted SHA256 digest (or any other signature digest)

require 'openssl'
require 'json'
require 'hashr'
require 'base64'
require 'fileutils' # required by older ruby versions, auto-loaded by rubyv > 2 

# setting defaults (todo: other ciphers and digests are untested)
DEFAULT_CRYPTOSET = {
  :vaultinfo_signkey_cipher => 'aes-256-cbc',
  :data_signkey_cipher => 'aes-256-cbc',
  :data_cipher => 'aes-256-cbc',
  :vaultinfo_signkey_digest => 'sha256',
  :data_signkey_digest => 'sha256',
  :data_digest => 'sha256',
  :vaultinfo_valkey_digest => 'sha256',
  :data_valkey_digest => 'sha256',
  :vaultinfo_digest => 'sha256'
}

DEFAULT_DATA = 'EMPTY'

# extend Hash with methods to produce repeatble and consistant digests, todo: move to PreVault
class Hash

  # iterate over all keys and yield the key + a digest of the value and 
  def allkeys_valdigest( options = { :digest => DEFAULT_CRYPTOSET[ :vaultinfo_digest ] } )
    each_key do |key|
      if self[ key ].respond_to? ( :each )
        yield key.to_s
        self[ key ].allkeys_valdigest{ |out| yield out }
      else
        # concatenate key and value
        yield key.to_s + self[ key ]
      end
    end
  end
  
  def digestable( options = { :digest => DEFAULT_CRYPTOSET[ :vaultinfo_digest ] } )
    # collect the keys + value digests
    kdgs = []
    allkeys_valdigest( :digest => options[ :digest ] ) { |kdg| kdgs << kdg }
    # sort them, because the order of a hash is unspecified, concatenate for the digest
    kdgs.sort.join
  end
  
end

# todo: make gem of this thing

# this loads data into hashr, either from a file or from json data
class PreVault < Hashr

  def initialize( source = {} )
    @original_filename = source[ :file ]
    super( JSON.parse( IO.read( source[ :file ] ) ) ) if not source[ :file ].nil?
    super( JSON.parse( source[ :json ] ) ) if not source[ :json ].nil?
    super( source ) if source[ :file ].nil? and source[ :json ].nil?
  end

  # todo: make private

  def validate_vaultinfo_valkey
    # check the signature of the vaultinfo validation key (public key of vaultinfo signkey), using the public key of the current user
    # use the current user public key (derived from the private key) from disk, not from the vault itself!
    # this is the only place to set @validation_key, so it is only available when it is validated
    vaultinfo_valkey_digest = OpenSSL::Digest.new( self.cryptoset.vaultinfo_valkey_digest )
    
    if @current_user_keyset.verify( vaultinfo_valkey_digest, Base64.strict_decode64( self.users.send( @user_info.name.to_sym ).vaultinfo_valkey_signature ), self.keysets.vaultinfo_valkey )
      @vaultinfo_validation_key = OpenSSL::PKey::RSA.new( Base64.strict_decode64( self.keysets.vaultinfo_valkey ) )
      return true
    else
      raise "Unable to verify the vaultinfo validation key"
    end
  end
  
  def validate_data_valkey
    # check the signature of the validation key (public key of signkey), using the public key of the current user
    # use the current user public key (derived from the private key) from disk, not from the vault itself!
    # this is the only place to set @data_validation_key, so it is only available when it is validated
    data_valkey_digest = OpenSSL::Digest.new( self.cryptoset.data_valkey_digest )
    
    if @current_user_keyset.verify( data_valkey_digest, Base64.strict_decode64( self.users.send( @user_info.name.to_sym ).data_valkey_signature ), self.keysets.data_valkey )
      @data_validation_key = OpenSSL::PKey::RSA.new( Base64.strict_decode64( self.keysets.data_valkey ) )
      return true
    else
      raise "Unable to verify the data validation key"
    end
  end
  
  def validate_vaultinfo
    # never validate the vaultinfo without first validating the validation key
    self.validate_vaultinfo_valkey
    # check the signature of the vaultinfo 
    vaultinfo_digest = OpenSSL::Digest.new( self.cryptoset.vaultinfo_digest )
    if @vaultinfo_validation_key.verify( vaultinfo_digest, Base64.strict_decode64( self.signatures.vaultconfig_signature ), self.except( :signatures, :data, :initvectors  ).digestable( :digest => self.cryptoset.vaultinfo_digest ) )
      return true
    else
      raise "Vault info validation failed"
    end
  end
  
  def validate_data
    # this will also validate the validation key and the vault info itself
    # never read data without validating the vault info 
    self.validate_vaultinfo
    self.validate_data_valkey
    # check the signature of the data
    data_digest = OpenSSL::Digest.new( self.cryptoset.data_digest )
    if @data_validation_key.verify( data_digest, Base64.strict_decode64( self.signatures.data_signature ), self.data.encrypted_data )
      return true
    else
      raise "Data validation failed"
    end
  end

  def sign_data
    # decrypt keysets.signkey, validate vaultinfo first
    self.validate_vaultinfo
    self.validate_data_valkey # not strictly needed..
    # cannot sign data if current user is not owner
    raise "Must be owner to sign data" if self.users.send( @user_info.name.to_sym ).data_sign_symkey.nil?
    data_signkey_cipher = OpenSSL::Cipher.new( self.cryptoset.data_signkey_cipher )
    data_signkey_cipher.decrypt
    data_signkey_cipher.iv = Base64.strict_decode64( self.initvectors.data_signkey_init_vector )
    data_signkey_cipher.key = @current_user_keyset.private_decrypt( Base64.strict_decode64( self.users.send( @user_info.name.to_sym ).data_sign_symkey ) )
    data_signkeypair = OpenSSL::PKey::RSA.new( data_signkey_cipher.update( Base64.strict_decode64( self.keysets.data_signkey ) ) + data_signkey_cipher.final )
    
    # sign data
    data_digest = OpenSSL::Digest.new( self.cryptoset.data_digest )
    self.signatures.data_signature = Base64.strict_encode64( data_signkeypair.sign( data_digest, self.data.encrypted_data ) ) 
  end
  
  def sign_vaultinfo

    raise "Must be owner to sign vaultinfo" if self.users.send( @user_info.name.to_sym ).vaultinfo_sign_symkey.nil?
    vaultinfo_signkey_cipher = OpenSSL::Cipher.new( self.cryptoset.vaultinfo_signkey_cipher )
    vaultinfo_signkey_cipher.decrypt
    vaultinfo_signkey_cipher.iv = Base64.strict_decode64( self.initvectors.vaultinfo_signkey_init_vector )
    vaultinfo_signkey_cipher.key = @current_user_keyset.private_decrypt( Base64.strict_decode64( self.users.send( @user_info.name.to_sym ).vaultinfo_sign_symkey ) )
    vaultinfo_signkeypair = OpenSSL::PKey::RSA.new( vaultinfo_signkey_cipher.update( Base64.strict_decode64( self.keysets.vaultinfo_signkey ) ) + vaultinfo_signkey_cipher.final )
    
    vaultinfo_digest = OpenSSL::Digest.new( self.cryptoset.vaultinfo_digest )    
    self.signatures.vaultconfig_signature = Base64.strict_encode64( vaultinfo_signkeypair.sign( vaultinfo_digest, self.except( :signatures, :data, :initvectors  ).digestable( :digest => self.cryptoset.vaultinfo_digest ) ) )
    
  end
  
  def write_to_disk( options = { :filename => "#{self.name}.vault" } )
    # write the vault to disk
    # todo: maybe validate before writing?
    options[ :filename ] = @original_filename if not @original_filename.nil?
    File.open( options[ :filename ],"wb") do |f|
      f.write(JSON.pretty_generate(self))
    end
  end

end


# todo init vectors belong by their respective data, not in cryptoset, make separate init vector root in hash
# todo add auto-increasing version number on every vault re-sign, with date and time
# todo: unit tests

class MultiVault < PreVault

  # this loads multivault from a file, or creates a new one with a name
  # it loads the current user key or fails if no key is present
  # action can be: :load => 'file', :create => 'new name'
  # example mv = Multivault.new( :action => { :load => 'somevault' } )  ( or with , :cryptoset => { .... }
  def initialize( options = { :action => {}, :cryptoset => {} } )
    # load current user key if it exists
    current_user_keyfile = File.join( ENV['HOME'], '.multivault', 'user_private_key' )
    current_user_info_file = File.join( ENV['HOME'], '.multivault', 'user_info' )
    if File.exists?( current_user_keyfile )
      @current_user_keyset = OpenSSL::PKey::RSA.new File.read( current_user_keyfile )
      if File.exists?( current_user_info_file )
      then
        @user_info = Hashr.new( JSON.parse( IO.read( current_user_info_file ) ) )
      else
        # an exeption is raised if keyfile exists without user info
        raise "Current user does not have an info file, please create one"
      end
    else
      # cannot proceed without a keyfile
      raise "Current user does not have a keyfile, please create one"
    end    
    # if action is load from file, then do so
    super( :file => options[ :action ][ :load ]  ) if not options[ :action ][ :load ].nil?
    # or create new vault
    begin
      newvault = Hashr.new # PreVault.new doesn't work...?
      # set name
      newvault.name = options[ :action ][ :create ]
      # set cryptoset, merge default into cryptoset options
      if options[ :cryptoset ].nil?
        newvault.cryptoset = DEFAULT_CRYPTOSET
      else
        newvault.cryptoset = DEFAULT_CRYPTOSET.merge( options[ :cryptoset ] )
      end
      # create the current user, will be the only user and owner initialiy
      newvault.users = { @user_info.name.to_sym => { :user_pubkey => Base64.strict_encode64( @current_user_keyset.public_key.to_der ) } }
      
      # create the symmetric key cipher to encrypt the vaultinfo sign key
      vaultinfo_signkey_cipher = OpenSSL::Cipher.new( newvault.cryptoset.vaultinfo_signkey_cipher )
      vaultinfo_signkey_cipher.encrypt
      # store the initialization vector (plain base64)
      newvault[ :initvectors ] = { :vaultinfo_signkey_init_vector => Base64.strict_encode64( vaultinfo_signkey_cipher.random_iv ) }
      # store the symmetric key, but encrypt it with the current user public key, so only the current user can read it
      newvault.users.send( @user_info.name.to_sym ).vaultinfo_sign_symkey = Base64.strict_encode64( @current_user_keyset.public_encrypt( vaultinfo_signkey_cipher.random_key ) )
      
      # todo: a separate signkey for data and the vault itself would create the possibility of separate data and vault read/write rights
      
      # create vaultinfo signkey, public part is vaultinfo validation key, private part will be encypted with vaultinfo_signkey_cipher
      vaultinfo_signkeypair = OpenSSL::PKey::RSA.new( 4096 )
      # store validation key (public part of signkey) in strict RFC 4648 to avoid problems with signature validation, 
      # use DER format for the same reason (pem is not properly specified)
      newvault.keysets = { :vaultinfo_valkey => Base64.strict_encode64( vaultinfo_signkeypair.public_key.to_der ) }
      # encrypt private vaultinfo_signkey with with vaultinfo_sign_symkey and store base64
      newvault.keysets.vaultinfo_signkey = Base64.strict_encode64( vaultinfo_signkey_cipher.update( vaultinfo_signkeypair.to_der ) + vaultinfo_signkey_cipher.final )
    
      # create the symmetric key cipher to encrypt the data sign key
      data_signkey_cipher = OpenSSL::Cipher.new( newvault.cryptoset.data_signkey_cipher )
      data_signkey_cipher.encrypt
      # store the initialization vector (plain base64)
      newvault.initvectors.data_signkey_init_vector = Base64.strict_encode64( data_signkey_cipher.random_iv ) 
      # store the symmetric key, but encrypt it with the current user public key, so only the current user can read it
      newvault.users.send( @user_info.name.to_sym ).data_sign_symkey = Base64.strict_encode64( @current_user_keyset.public_encrypt( data_signkey_cipher.random_key ) )
      
      
      # create data signkey, public part is data validation key, private part will be encypted with data_signkey_cipher
      data_signkeypair = OpenSSL::PKey::RSA.new( 4096 )
      # store validation key (public part of signkey) in strict RFC 4648 to avoid problems with signature validation, 
      # use DER format for the same reason (pem is not properly specified)
      newvault.keysets.data_valkey = Base64.strict_encode64( data_signkeypair.public_key.to_der ) 
      # encrypt private data_signkey with with data_sign_symkey and store base64
      newvault.keysets.data_signkey = Base64.strict_encode64( data_signkey_cipher.update( data_signkeypair.to_der ) + data_signkey_cipher.final )     
      
      
      
      
      # create the symmetric key cipher to encrypt the data
      data_cipher = OpenSSL::Cipher.new( newvault.cryptoset.data_cipher )
      data_cipher.encrypt
      # store the initialization vector (plain base64)
      newvault.initvectors.data_init_vector = Base64.strict_encode64( data_cipher.random_iv )
      # store the symmetric key, but encrypt it with the current user public key, so only the current user can read it
      newvault.users.send( @user_info.name.to_sym ).data_symkey = Base64.strict_encode64( @current_user_keyset.public_encrypt( data_cipher.random_key ) )
      
      # encrypt the data
      newvault.data = { :encrypted_data => Base64.strict_encode64( data_cipher.update( DEFAULT_DATA ) + data_cipher.final ) }
      
      # there are 4 type of signatures, the data signature, the vaultinfo validation key signature (one for every user), the vaultconfig signature and the data validation key signature
      # note that signatures are derived from what is actualy in the vault, the Base64 encoded, encrypted data, not on the data or the encrypted data itself
      
      data_digest = OpenSSL::Digest.new( newvault.cryptoset.data_digest )
      newvault.signatures = { :data_signature => Base64.strict_encode64( data_signkeypair.sign( data_digest, newvault.data.encrypted_data ) ) }
      
      # use the private key of the current user (owner) to sign the vaultinfo validation key, again on what is actualy in the vault (the base64 encoded validation key)
      vaultinfo_valkey_digest = OpenSSL::Digest.new( newvault.cryptoset.vaultinfo_valkey_digest )
      newvault.users.send( @user_info.name.to_sym ).vaultinfo_valkey_signature = Base64.strict_encode64( @current_user_keyset.sign( vaultinfo_valkey_digest, newvault.keysets.vaultinfo_valkey ) )
      
      # use the private key of the current user (owner) to sign the data validation key, again on what is actualy in the vault (the base64 encoded validation key)
      data_valkey_digest = OpenSSL::Digest.new( newvault.cryptoset.data_valkey_digest )
      newvault.users.send( @user_info.name.to_sym ).data_valkey_signature = Base64.strict_encode64( @current_user_keyset.sign( data_valkey_digest, newvault.keysets.data_valkey ) )
      
      # the signature on the vault itself should be consistent and repeatable, but hashes do not have any inherent order
      # so the digest is based on: a concatenated( sorted list of key + valuedigest concatenated ), again based on the values actualy in the vault.
      # all except the data and signatures themselves are used to create the signature
      # the signature is make with signkey
      vaultinfo_digest = OpenSSL::Digest.new( newvault.cryptoset.vaultinfo_digest )
      newvault.signatures.vaultconfig_signature = Base64.strict_encode64( vaultinfo_signkeypair.sign( vaultinfo_digest, newvault.except( :signatures, :data, :initvectors  ).digestable( :digest => newvault.cryptoset.vaultinfo_digest ) ) )
      
      super( newvault )
    end if not options[ :action ][ :create ].nil?
  end
  
  def read_data
    self.validate_data
    data_cipher = OpenSSL::Cipher.new( self.cryptoset.data_cipher )
    data_cipher.decrypt
    data_cipher.iv = Base64.strict_decode64( self.initvectors.data_init_vector )
    data_cipher.key = @current_user_keyset.private_decrypt( Base64.strict_decode64( self.users.send( @user_info.name.to_sym ).data_symkey ) )
    data_cipher.update( Base64.strict_decode64( self.data.encrypted_data ) ) + data_cipher.final
  end
  
  def write_data( newdata_plain )
    # set and sign
    raise "Must have data write capabilities to change data" if self.users.send( @user_info.name.to_sym ).data_sign_symkey.nil?
    raise "Vault should not be empty" if newdata_plain.empty? # todo: allow empty data
    data_cipher = OpenSSL::Cipher.new( self.cryptoset.data_cipher )
    data_cipher.encrypt
    data_cipher.key = @current_user_keyset.private_decrypt( Base64.strict_decode64( self.users.send( @user_info.name.to_sym ).data_symkey ) )
    self.initvectors.data_init_vector = Base64.strict_encode64( data_cipher.random_iv ) 
    # self.sign_vaultinfo # if we move data_init_vector to data we don't have to re-sign the vault itself for write_data
    self.data.encrypted_data = Base64.strict_encode64( data_cipher.update( newdata_plain ) + data_cipher.final )
    self.sign_data
  end
  
  def add_user( request_file, options = { :make_owner => false } )
    
    # todo: check if vault name matches request
    
    raise "Must be owner to add user" if self.users.send( @user_info.name.to_sym ).vaultinfo_sign_symkey.nil?
    # load request from file
    access_request = PreVault.new( :file => request_file )
    
    # validate vault itself first (will also validate valkey)
    self.validate_vaultinfo
    
    # validate signature on vaultinfo valkey with user pubkey and vaultinfo valkey from vault
    newuser_pubkey = OpenSSL::PKey::RSA.new( Base64.strict_decode64( access_request.user_pubkey ) )
    vaultinfo_valkey_digest = OpenSSL::Digest.new( self.cryptoset.vaultinfo_valkey_digest )
    raise "Unable to validate vaultinfo_valkey signature for new user" if not newuser_pubkey.verify( vaultinfo_valkey_digest , Base64.strict_decode64( access_request.vaultinfo_valkey_signature ), self.keysets.vaultinfo_valkey )
    
    # validate signature on data valkey with user pubkey and data valkey from vault
    data_valkey_digest = OpenSSL::Digest.new( self.cryptoset.data_valkey_digest )
    raise "Unable to validate data_valkey signature for new user" if not newuser_pubkey.verify( data_valkey_digest , Base64.strict_decode64( access_request.data_valkey_signature ), self.keysets.data_valkey )    
    
    
    # add user public key and validation signatures
    self.users[ access_request.user_name.to_sym ] = { :user_pubkey => access_request.user_pubkey, :vaultinfo_valkey_signature => access_request.vaultinfo_valkey_signature, :data_valkey_signature => access_request.data_valkey_signature }
    
    # give the user a symmetric key for data decryption, encrypted with the newusers' public key
    self.users.send( access_request.user_name ).data_symkey = Base64.strict_encode64( newuser_pubkey.public_encrypt( @current_user_keyset.private_decrypt( Base64.strict_decode64( self.users.send( @user_info.name.to_sym ).data_symkey ) ) ) )
    
    # re-sign vault info
    self.sign_vaultinfo
    
    # todo: do something with make_owner if true
    
  end
  
  def del_user( username )
    # deletes a user
    # todo: owner cannot delete self, sign function needs users' signkey_symkey
    
    raise "Must have vaultinfo write capabilities to delete user" if self.users.send( @user_info.name.to_sym ).vaultinfo_sign_symkey.nil?
    raise "No such user" if self.users.send( username.to_sym ).nil?
    
    self.validate_vaultinfo
    
    self.users.delete( username.to_sym )
    
    self.sign_vaultinfo
  
  end
  
  def add_data_write( username )
    # this will add data write capability to a user by adding data_sign_symkey for the user
    raise "Must have vaultinfo_write capabilities to change user info" if self.users.send( @user_info.name.to_sym ).vaultinfo_sign_symkey.nil?
    raise "Must have data write capabilities to give another user data write access" if self.users.send( @user_info.name.to_sym ).data_sign_symkey.nil?
    raise "No such user" if self.users.send( username.to_sym ).nil?
    raise "User already has data write capabilities" if not self.users.send( username.to_sym ).data_sign_symkey.nil?
    
    self.validate_vaultinfo
    # add data write capabilities by adding sign_symkey encypted with public key of the new data writer
    newcap_pubkey = OpenSSL::PKey::RSA.new( Base64.strict_decode64( self.users.send( username.to_sym ).user_pubkey ) )
    self.users.send( username.to_sym ).data_sign_symkey =  Base64.strict_encode64( newcap_pubkey.public_encrypt(  @current_user_keyset.private_decrypt( Base64.strict_decode64( self.users.send( @user_info.name.to_sym ).data_sign_symkey ) ) ) )
    
    self.sign_vaultinfo
  end
  
  def del_data_write( username ) 
    # this will remove data write capability by removing data_sign_symkey for a user
    raise "Must have vaultinfo_write capabilities to change user info" if self.users.send( @user_info.name.to_sym ).vaultinfo_sign_symkey.nil?
    raise "No such user" if self.users.send( username.to_sym ).nil?
    raise "User doesn't have data write capabilities" if self.users.send( username.to_sym ).data_sign_symkey.nil?
    
    self.validate_vaultinfo
    self.users.send( username.to_sym ).delete( :data_sign_symkey )
    self.sign_vaultinfo
  end
  
  def add_vaultinfo_write( username)
    # this will add vaultinfo write capabilities to a user, allowing to create users
    raise "Must have vaultinfo_write capabilities to change user info" if self.users.send( @user_info.name.to_sym ).vaultinfo_sign_symkey.nil?
    raise "No such user" if self.users.send( username.to_sym ).nil?
    raise "User already has vaultinfo write capabilities" if not self.users.send( username.to_sym ).vaultinfo_sign_symkey.nil?
    
    self.validate_vaultinfo
    # add vaultinfo write capabilities by adding sign_symkey encypted with public key of the new vault administrator
    newcap_pubkey = OpenSSL::PKey::RSA.new( Base64.strict_decode64( self.users.send( username.to_sym ).user_pubkey ) )
    self.users.send( username.to_sym ).vaultinfo_sign_symkey =  Base64.strict_encode64( newcap_pubkey.public_encrypt(  @current_user_keyset.private_decrypt( Base64.strict_decode64( self.users.send( @user_info.name.to_sym ).vaultinfo_sign_symkey ) ) ) )
    
    self.sign_vaultinfo
    
  end
  
  def del_vaultinfo_write( username )
    # this will delete vaultinfo write capabilities
    raise "Must have vaultinfo_write capabilities to change user info" if self.users.send( @user_info.name.to_sym ).vaultinfo_sign_symkey.nil?
    raise "No such user" if self.users.send( username.to_sym ).nil?
    raise "User doesn't have vaultinfo write capabilities" if self.users.send( username.to_sym ).vaultinfo_sign_symkey.nil?
    
    self.validate_vaultinfo
    self.users.send( username.to_sym ).delete( :vaultinfo_sign_symkey )
    self.sign_vaultinfo
    
  end
  
  def show_users
    # show users and their rights
    # not implemented yet
  end
  
  def change_vault_name
    # notimplemented yet
  end
  
  def re_cipher
    # re-crypting (with another cipher) not implemented yet
  end
  
  def re_digest
    # ruminate not implemented yet
  end
  
  def whoami
    # not implemented yet
  end
  
  def current_user_name
    # returns current user name (for MVaultHelper )
    @user_info.name
  end
  
  def current_user_pubkey
    # returns current user pubkey in base64 (for MVaultHelper )
    Base64.strict_encode64( @current_user_keyset.public_key.to_der )
  end
  
  def current_user_key
    # returns current user keypair (for MVaultHelper)
    @current_user_keyset
  end
  

    # todo: create files section to encrypt/decrypt external files
    # while chunk = io.read(1024)
    #   out << cipher.update(chunk)
    # end
    # out << cipher.final
   
  

end

class MVaultHelper < PreVault
  
  def create_key( username )
    # todo: ask user for password on private key
    # create key and write it if it doesn't exist
    keyfile = File.join( ENV['HOME'], '.multivault', 'user_private_key' )
    raise "Keyfile already exists, please use delete_key first" if File.exists?( keyfile )
    new_keyset = OpenSSL::PKey::RSA.new( 4096 )
    FileUtils.mkdir_p File.dirname keyfile
    open( keyfile, 'w' ) { |io| io.write( new_keyset.to_pem ) }
    # write user info
    userfile = File.join( ENV['HOME'], '.multivault', 'user_info' )
    open( userfile, 'w' ) { |io| io.write( JSON.pretty_generate( { :name => username } ) ) }
    FileUtils.chmod( "u=r,og-rwx", keyfile )
    FileUtils.chmod( "u=r,og-rwx", userfile )
    FileUtils.chmod( "u=rx,og-rwx", File.dirname( keyfile ) )
  end
  
  def delete_key
    keyfile = File.join( ENV['HOME'], '.multivault', 'user_private_key' )
    userfile = File.join( ENV['HOME'], '.multivault', 'user_info' )
    raise "Keyfile doesn't exists, cannot delete something which isn't there" if not File.exists?( keyfile )
    FileUtils.chmod( "u=rwx", File.dirname( keyfile ) )
    FileUtils.chmod( "u=rw", keyfile )
    FileUtils.chmod( "u=rw", userfile )
    File.delete( keyfile )
    File.delete( userfile )
    Dir.rmdir( File.dirname( keyfile ) )
  end
  
  def request_access( vault_file, request_file )
    # creates a json file with the users' public key and a personal signature on the validation key
    # todo: create two signatures when validation key becomes separate data and vault validation key
    # todo: sign the request (is that usefull without external pubkey source?)
    # the owner who adds the user should trust or validate the origin and content of the access request
    vault = MultiVault.new( :action => { :load => vault_file } )
    access_request = PreVault.new( { :user_name => vault.current_user_name, :user_pubkey => vault.current_user_pubkey, :access_to => vault.name } )
    
    # use the private key of the current user to sign the vaultinfo validation key
    vaultinfo_valkey_digest = OpenSSL::Digest.new( vault.cryptoset.vaultinfo_valkey_digest )
    access_request.vaultinfo_valkey_signature = Base64.strict_encode64( vault.current_user_key.sign( vaultinfo_valkey_digest, vault.keysets.vaultinfo_valkey ) )
    
    # use the private key of the current user to sign the data validation key
    data_valkey_digest = OpenSSL::Digest.new( vault.cryptoset.data_valkey_digest )
    access_request.data_valkey_signature = Base64.strict_encode64( vault.current_user_key.sign( data_valkey_digest, vault.keysets.data_valkey ) )    
    
    access_request.write_to_disk( :filename => request_file )
    
  end
  
end

MVAULT = MVaultHelper.new
