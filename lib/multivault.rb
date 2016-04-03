# jeroen vriesman <jeroen.vriesman@root-it.biz>

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

# setting defaults
DEFAULT_CRYPTOSET = {
  :signkey_cipher => 'aes-128-cbc',
  :data_cipher => 'aes-128-cbc',
  :signkey_digest => 'sha256',
  :data_digest => 'sha256',
  :valkey_digest => 'sha256'
}

DEFAULT_DATA = 'EMPTY'

# this loads data into hashr, either from a file or from json data
class Hashr_loader < Hashr
  def initialize( source = {} )
    super( JSON.parse( IO.read( source[ :file ] ) ) ) if not source[ :file ].nil?
    super( JSON.parse( source[ :json ] ) ) if not source[ :json ].nil?
    super( source ) if source[ :file ].nil? and source[ :json ].nil?
  end
end

# todo make global constant keytool

class MultiVault < Hashr_loader

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
      newvault = Hashr.new
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
      
      # create the symmetric key cipher to encrypt the sign key
      signkey_cipher = OpenSSL::Cipher.new( newvault.cryptoset.signkey_cipher )
      signkey_cipher.encrypt
      # store the initialization vector (plain base64)
      newvault.cryptoset.signkey_init_vector = Base64.strict_encode64( signkey_cipher.random_iv )
      # store the symmetric key, but encrypt it with the current user public key, so only the current user can read it
      newvault.users.send( @user_info.name.to_sym ).sign_symkey = Base64.strict_encode64( @current_user_keyset.public_encrypt( signkey_cipher.random_key ) )
      
      # create signkey, public part is validation key, private part will be encypted with signkey_cipher
      signkeypair = OpenSSL::PKey::RSA.new( 4096 )
      # store validation key (public part of signkey) in strict RFC 4648 to avoid problems with signature validation, 
      # use DER format for the same reason (pem is not properly specified)
      newvault.keysets = { :valkey => Base64.strict_encode64( signkeypair.public_key.to_der ) }
      # encrypt private signkey with with sign_symkey and store base64
      newvault.keysets.signkey = Base64.strict_encode64( signkey_cipher.update( signkeypair.to_der ) + signkey_cipher.final )
      
      # create the symmetric key cipher to encrypt the data
      data_cipher = OpenSSL::Cipher.new( newvault.cryptoset.data_cipher )
      data_cipher.encrypt
      # store the initialization vector (plain base64)
      newvault.cryptoset.data_init_vector = Base64.strict_encode64( data_cipher.random_iv )
      # store the symmetric key, but encrypt it with the current user public key, so only the current user can read it
      newvault.users.send( @user_info.name.to_sym ).data_symkey = Base64.strict_encode64( @current_user_keyset.public_encrypt( data_cipher.random_key ) )
      
      # encrypt the data
      newvault.data = { :encrypted_data => Base64.strict_encode64( data_cipher.update( DEFAULT_DATA ) + data_cipher.final ) }
      
      # there are 3 type of signatures, the data signature, the validation key signature (oen for every user) and the vaultconfig signature.
      # the validation key signature and the vaultconfig signature share the same cipher and digest algorithms
      # note that signatures are derived from what is actualy in the vault, the Base64 encoded, encrypted data, not on the data or the encrypted data itself
      
      data_digest = OpenSSL::Digest.new( newvault.cryptoset.data_digest )
      newvault.signatures = { :data_signature => Base64.strict_encode64( signkeypair.sign( data_digest, newvault.data.encrypted_data ) ) }
      
      # use the private key of the current user (owner) to sign the validation key, again on what is actualy in the vault (hte base64 encoded validation key)
      valkey_digest = OpenSSL::Digest.new( newvault.cryptoset.valkey_digest )
      newvault.users.send( @user_info.name.to_sym ).valkey_signature = Base64.strict_encode64( @current_user_keyset.sign( valkey_digest, newvault.keysets.valkey ) )
      
      # the signature on the vault itself should be consistent and repetable, but hashes do not have any inherent order
      # so the digest is based on: a concatenated( sorted list of key/values concatenated ), again based on the values actualy in the vault.
      # all except the signatures thmeselves are used to create the signature
      
      super( newvault )
    end if not options[ :action ][ :create ].nil?
  end
  
  
  # will read or create the private key for the current user (no passwd)
  def current_user_keyset
    # use File.join for linux/windows compatibility
    keyfile = File.join( ENV['HOME'], '.multivault', 'user_private_key' )
    # create if not exists
    if File.exists? keyfile 
      @current_user_keyset = OpenSSL::PKey::RSA.new File.read keyfile
    else
      @current_user_keyset = OpenSSL::PKey::RSA.new 4096
      FileUtils.mkdir_p File.dirname keyfile
      open keyfile, 'w' do |io| io.write @current_user_keyset.to_pem end
      FileUtils.chmod "u=r,og-rwx", keyfile
      FileUtils.chmod "u=rx,og-rwx", File.dirname( keyfile )
    end
  end
  
  def create( plain_data, options = { :data_cipher => 'aes-128-cbc', :signature_digest => 'sha256', :sign_key_cipher => 'aes-128-cbc' } )
    # create will make the following parts of the vault:
    # for create the assumption is that current_user will be the owner, and initialy the only user
    # 1) config,json, a json with the settings, this is the @config (as an array, but will be json on disk), and json pp for signing
    # 2) a symmetric key, encrypted with current_user_public_key (not stored, method of the private key)
    # 3) data, encrypted with the SYMKEY
    # 4) a "signkey", encrypted with a random symmetric key sign_key_symkey 
    # 5) sign_key_symkey encrypted with current_user_public_key
    # 6) the "validation key", which is the public key of the signkey
    # 7) a signature on the validation key (owner-bound)
    # 8) the "master" signature, a signature on everything exept the signature itself.
    # n.b: a new user needs the validation key to create an add-me request, a user needs the validation key and checks his own signature on the validation key
    # an owner has access to the private "signkey", but the owner would still like to validate (prevent tampering with signkey), so owner also needs a signature on 
    # the validation key
    
    # assuming io is the IO representing your uploaded file 
    # and out is the IO you are writing to
    # while chunk = io.read(1024)
    #   out << cipher.update(chunk)
    # end
    # out << cipher.final
    
    # do not use ecb mode, todo: check for ecb mode request
    
    # create the config array
    @config[ :data_cipher ] = options[ :data_cipher ]
    @config[ :sign_key_cipher ] = options[ :sign_key_cipher ]
    @config[ :name ] = @name
    @config[ :signature_digest ] = options[ :signature_digest ]
    
    # initialize the cipher and create symmetric key encrypted with the owners public key
    data_cipher = OpenSSL::Cipher.new( @config[ :data_cipher ] )
    data_cipher.encrypt
    @symkey = @current_user_keyset.public_encrypt data_cipher.random_key # only owner/creator has the private key to read this 
    
    # create an encrypted version of the data, store the initialization vector
    @config[ :data_initialization_vector ] = data_cipher.random_iv # init vector
    @data_encrypted = data_cipher.update( plain_data ) + data_cipher.final
    
    # create the sign key and encrypt with symmetric key, the corresponding symmetric key is encypted with owner public key
    
    
    
  end
  
  private :current_user_keyset

end
