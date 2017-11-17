$ErrorActionPreference = "Stop";

# . T:\psforeman\psforeman.ps1
# [System.Net.ServicePointManager]::CheckCertificateRevocationList = $false;
# [System.Net.ServicePointManager]::ServerCertificateValidationCallback

## Global Var storing important values!
	if($Global:PSForeman_Storage -eq $null){
		$Global:PSForeman_Storage = @{
				SESSIONS = @()
				DEFAULT_SESSION = $null	
				TRUST_SSL = $true
				DEBUG_OPTIONS = @{
						ENABLED = $false
					}
			}
	}


## Helpers
#Make calls to a zabbix server url api.
	
	Function Foreman_UrlEncode {
		param($Value)
		
		try {
			$Encoded = [System.Web.HttpUtility]::URLEncode($Value);
			return $Encoded;
		} catch {
			write-verbose "Failure on urlencode. Data:$Value. Error:$_";
			return $Value;
		}
	}
	
	#Converts a hashtable to a URLENCODED format to be send over HTTP requests.
	Function Foreman_BuildURLEncoded {
		param($Data)
		
		
		$FinalString = @();
		$Data.GetEnumerator() | %{
			write-verbose "$($MyInvocation.InvocationName): Converting $($_.Key)..."
			$ParamName = Foreman_UrlEncode $_.Key; 
			$ParamValue = Foreman_UrlEncode $_.Value; 
		
			$FinalString += "$ParamName=$ParamValue";
		}

		$FinalString = $FinalString -Join "&";
		return $FinalString;
	}

	Function Foreman_CallUrl {
		param(
			[object]$data = $null
			,$url = $null
			,$method = "POST"
			,$contentType = "application/json"
			,$Headers = @{}
			,$HttpFail = @()
			,$Credentials 	= $null
			,$Session		= $null
			,$Cookies		= $null
			,$OutData		= $null
			,$AutoRedirect	= $null
			,[switch]$CheckSetCookie = $false
			,$Authentication = @{}
		)
		$ErrorActionPreference="Stop";
		
		$DebugOpts 	= @{}
		$OutResult	= @{
			session = @{cookies=$null}
		};
		$DebugOpts["OutResult"] = $OutResult;
		
		if($OutData -is [hashtable]){
			$OutData["results"] = $OutResult;
		}
		
		if($Global:PSForeman_Storage.DEBUG_OPTIONS.ENABLED){
			$Global:PSForeman_Storage.DEBUG_OPTIONS["CALLURL"] = $DebugOpts;
		}

		try {
			if(!$data){
				$data = "";
			}
			
			if(-not($Headers -is [hashtable])){
				$Headers = @{};
			}
		
			if($Method -eq "GET" -and $data){
				write-verbose "$($MyInvocation.InvocationName): Encoding the data for GET... Data: $data"
				$EncodedDataForGet = Foreman_BuildURLEncoded $data;
				$url += '?'+$EncodedDataForGet;
				$data = "";
			} else {
			
				if($data -is [hashtable]){
					write-verbose "Converting input object to json string..."
					$data = Foreman_ConvertToJson $data;
				}
			
				write-verbose "$($MyInvocation.InvocationName):  json that will be send is: $data"
			}
		
			write-verbose "$($MyInvocation.InvocationName): URL:$URL"
		
			write-verbose "$($MyInvocation.InvocationName):  Creating WebRequest method... Url: $url. Method: $Method ContentType: $ContentType";
			$Web = [System.Net.WebRequest]::Create($url);
			$DebugOpts["Web"]=$Web;
			$Web.ServerCertificateValidationCallback = {$true}
			$Web.Method = $method;
			$Web.ContentType = $contentType
			if($AutoRedirect -ne $null){
				$Web.AllowAutoRedirect = $AutoRedirect
			}
			
			$CookieContainer = New-Object Net.CookieContainer;
			
			
			if($Cookies){
				write-verbose "$($MyInvocation.InvocationName): Adding cookies manually";
				
				$Cookies.GetEnumerator() | %{
					$CookieName = $_.Key;
					$CookieValue = $_.Value;
					$NewCookie = New-Object System.Net.Cookie($CookieName,$CookieValue);
					$CookieContainer.add($NewCookie);
				}
			}
			
			if($Session){
				write-verbose "$($MyInvocation.InvocationName): Session enabled. Adding cookies!"
				
				$Session.Cookies | ?{$_} | %{
						write-verbose "$($MyInvocation.InvocationName): Cookie $($_.Name) imported!"
						$CookieContainer.add($_);
				}
			}
			
			
			$Web.CookieContainer = $CookieContainer;
			
			
			if($Global:PSForeman_Storage.TRUST_SSL -eq $false){
				$Web.ServerCertificateValidationCallback = {$true};
			}
			
			
			if($Credentials -and !$Authentication.User){
				$Authentication['User'] = $Credentials.GetNetworkCredential().UserName
				$Authentication['Password'] = $Credentials.GetNetworkCredential().Password
			}

			if($Authentication.User -and !$Headers.Contains("Authorization")){
				$AuthType = $Authentication.Type;
				
				if(!$AuthType){
					$AuthType = "Basic";
				}
				
				if($AuthType -eq "Basic"){
					$AuthorizationData = 'Basic '+( Foreman_Base64 "$($Authentication.User):$($Authentication.Password)" )
					write-verbose "$($MyInvocation.InvocationName):  Adding basic authentication: $AuthorizationData"
					$Headers["Authorization"] = $AuthorizationData;
				}	
			}
			
			$Headers.GetEnumerator() | %{
				write-verbose "$($MyInvocation.InvocationName): Adding header $($_.Key) $($_.Value)"
				
				$PossibleProp = $_.Key.replace("-","");
				
				if($Web.psobject.properties[$PossibleProp]){
					$Web.psobject.properties[$PossibleProp].Value = $_.Value;
					return;
				}
				
				$Web.Headers.Add($_.Key,$_.Value);
			}

			
			
			if($data){
				#Determina a quantidade de bytes...
				[Byte[]]$bytes = [byte[]][char[]]$data;
				
				#Escrevendo os dados
				$Web.ContentLength = $bytes.Length;
				write-verbose "$($MyInvocation.InvocationName):  Bytes lengths: $($Web.ContentLength)"
				
				
				write-verbose "$($MyInvocation.InvocationName):  Getting request stream...."
				$RequestStream = $Web.GetRequestStream();
				
				
				try {
					write-verbose "$($MyInvocation.InvocationName):  Writing bytes to the request stream...";
					$RequestStream.Write($bytes, 0, $bytes.length);
				} finally {
					write-verbose "$($MyInvocation.InvocationName):  Disposing the request stream!"
					$RequestStream.Dispose() #This must be called after writing!
				}
			}
			
			
			
			write-verbose "$($MyInvocation.InvocationName):  Making http request... Waiting for the response..."
			try {
				$HttpResp = $Web.GetResponse();
			} catch {
				if($HttpFail){
					$BaseEx = $_.Exception.GetBaseException();
					if($BaseEx.Response){
						$HttpResp = $BaseEx.Response
					}
				} else {
					throw;
				}
			}
			
			
			
			$responseString  = $null;
			$DebugOpts["HttpResp"]=$HttpResp;
			if($HttpResp){
				write-verbose "$($MyInvocation.InvocationName):  charset: $($HttpResp.CharacterSet) encoding: $($HttpResp.ContentEncoding). ContentType: $($HttpResp.ContentType)"
				write-verbose "$($MyInvocation.InvocationName):  Getting response stream..."
				$ResponseStream  = $HttpResp.GetResponseStream();
				
				write-verbose "$($MyInvocation.InvocationName):  Response stream size: $($ResponseStream.Length) bytes"
				
				$IO = New-Object System.IO.StreamReader($ResponseStream);
				
				write-verbose "$($MyInvocation.InvocationName):  Reading response stream...."
				$responseString = $IO.ReadToEnd();
				
				write-verbose "$($MyInvocation.InvocationName):  response json is: $responseString"
				
				# Handling the cookies returned from response...
				$AllCookies 		= @();
				$AllCookiesNames	= @($AllCookies|%{$_.Name});
				
				#From response cookies prop...
				if($HttpResp.Cookies){
					$HttpResp.Cookies | %{
						write-verbose "$($MyInvocation.InvocationName): Updating path of cookie $($_.Name) from response object...";
						$_.Path = '/';
						$AllCookies += $_;
						$AllCookiesNames += $_.Name;
					}
				}

				#Cookies set in Set-Cookie with multiple values...
				if($CheckSetCookie){
					$i = -1;
					$HttpResp.Headers | ? { $i++; $_ -eq "Set-Cookie" } | %{
						$HeaderValue = $HttpResp.Headers.Get($i);
						write-verbose "Checking cookie in header Set-Cookie: $HeaderValue";
						$CookieParts 	= $HeaderValue -Split "; ";
						$NameValuePart	= $CookieParts[0];
						$NameValue		= $NameValuePart -split '=';
						$CookieName 	= $NameValue[0]
						$CookieValue	= $NameValue[1];
						
						if(-not ($AllCookiesNames -Contains $CookieName)){
							$AllCookies += New-Object System.Net.Cookie($CookieName,$CookieValue,'/');
							$AllCookiesNames += $CookieName;
							write-verbose "$($MyInvocation.InvocationName): Added $CookieName from Set-Cookie header response cookie list";
						}
					}
				}
				
				$DebugOpts["AllCookies"]=$AllCookies;
				$OutResult.session = @{cookies=$HttpResp.Cookies};
			}
			
			
			write-verbose "$($MyInvocation.InvocationName):  Response String size: $($responseString.length) characters! "
			return $responseString;
		} catch {		
			throw "ERROR_INVOKING_URL: $_";
		} finally {
			if($IO){
				$IO.close()
			}
			
			if($ResponseStream){
				$ResponseStream.Close()
			}
			
			<#
			if($HttpResp){
				write-host "Finazling http request stream..."
				$HttpResp.finalize()
			}
			#>

		
			if($RequestStream){
				write-verbose "Finazling request stream..."
				$RequestStream.Close()
			}
		}
	}

	Function Foreman_TranslateResponseJson {
		param($Response)
		
		#Converts the response to a object.
		write-verbose "$($MyInvocation.InvocationName): Converting from JSON!"
		$ResponseO = Foreman_ConvertFromJson $Response;
		
		write-verbose "$($MyInvocation.InvocationName): Checking properties of converted result!"
		#Check outputs
		if($ResponseO.error -ne $null){
			$ResponseError = $ResponseO.error;
			$MessageException = "$($ResponseError.message)";
			$Exception = New-Object System.Exception($MessageException)
			$Exception.Source = "ForemanAPI"
			throw $Exception;
			return;
		}
		
		
		#If not error, then return response result.
		if($ResponseO -is [hashtable]){
			return (New-Object PsObject -Prop $ResponseO.results);
		} else {
			return $ResponseO;
		}
	}

	#Converts objets to JSON and vice versa,
	Function Foreman_ConvertToJson($o) {
		
		if(Get-Command ConvertTo-Json -EA "SilentlyContinue"){
			write-verbose "$($MyInvocation.InvocationName): Using ConvertTo-Json"
			return Foreman_EscapeNonUnicodeJson(ConvertTo-Json $o);
		} else {
			write-verbose "$($MyInvocation.InvocationName): Using javascriptSerializer"
			Foreman_LoadJsonEngine
			$jo=new-object system.web.script.serialization.javascriptSerializer
			$jo.maxJsonLength=[int32]::maxvalue;
			return Foreman_EscapeNonUnicodeJson ($jo.Serialize($o))
		}
	}

	Function Foreman_ConvertFromJson([string]$json) {
	
		if(Get-Command ConvertFrom-Json  -EA "SilentlyContinue"){
			write-verbose "$($MyInvocation.InvocationName): Using ConvertFrom-Json"
			ConvertFrom-Json $json;
		} else {
			write-verbose "$($MyInvocation.InvocationName): Using javascriptSerializer"
			Foreman_LoadJsonEngine
			$jo=new-object system.web.script.serialization.javascriptSerializer
			$jo.maxJsonLength=[int32]::maxvalue;
			return $jo.DeserializeObject($json);
		}
		

	}
	
	Function Foreman_CheckAssembly {
		param($Name)
		
		if($Global:PsForeman_Loaded){
			return $true;
		}
		
		if( [appdomain]::currentdomain.getassemblies() | ? {$_ -match $Name}){
			$Global:PsForeman_Loaded = $true
			return $true;
		} else {
			return $false
		}
	}
	
	Function Foreman_LoadJsonEngine {

		$Engine = "System.Web.Extensions"

		if(!(Foreman_CheckAssembly $Engine)){
			try {
				write-verbose "$($MyInvocation.InvocationName): Loading JSON engine!"
				Add-Type -Assembly  $Engine
				$Global:PsForeman_Loaded = $true;
			} catch {
				throw "ERROR_LOADIING_WEB_EXTENSIONS: $_";
			}
		}

	}

	#Troca caracteres não-unicode por um \u + codigo!
	#Solucao adapatada da resposta do Douglas em: http://stackoverflow.com/a/25349901/4100116
	Function Foreman_EscapeNonUnicodeJson {
		param([string]$Json)
		
		$Replacer = {
			param($m)
			
			return [string]::format('\u{0:x4}', [int]$m.Value[0] )
		}
		
		$RegEx = [regex]'[^\x00-\x7F]';
		write-verbose "$($MyInvocation.InvocationName):  Original Json: $Json";
		$ReplacedJSon = $RegEx.replace( $Json, $Replacer)
		write-verbose "$($MyInvocation.InvocationName):  NonUnicode Json: $ReplacedJson";
		return $ReplacedJSon;
	}
	
	#Convers string to base64
	Function Foreman_Base64 {
		param($String, $Encoding = "UTF-8")
		
		$EncO = [System.Text.Encoding]::GetEncoding($Encoding);
		$Bytes = $EncO.GetBytes($String);
		
		return [Convert]::ToBase64String($Bytes);
	}
	
## Foreman Implementations!
	## This implementations depends on configured WEB SERVICE!
	## Our standard is: No value is passed on URL (tthats is, we no use :AttName)
	## Route maps to same Connector name!
	## We use this documentation as source: http://doc.Foreman.com/doc/manual/admin/5.0/en/html/genericinterface.html
	## We send all request as POST
	
	#Auxilary method calls builds
	Function BuildForemanApiUrlParams {
		param(
			 $Session
			,$ApiMethod
			,$HttpMethod
		)
		
		$UrlParams = @{
			Method = $HttpMethod
			HttpFail = 401
		}
		
		$UrlParams['url']  =  "$($Session.RestUrl)/$ApiMethod";
		
		if($Session.NoSession){
			$UrlParams.add('Credentials',$Session.SessionID.Credentials)
		} else {
			$UrlParams.add('Session',$Session.SessionID.HttpSession)
		}
		
		return $UrlParams;
	}
	
	Function New-ForemanSession {
		[CmdLetBinding()]
		param(
			$User
			,$Password
			,$Url
		)
		
		$MethodName = 'status'
		
		if(-not ($Url -like "*/api")){
			$Url += '/api'
		}	
		
		
		$Url2Call 	=  "$Url/status"
		
		$PassSecure	= ConvertTo-SecureString $Password -AsPlainText -Force;
		$Creds		= New-Object Management.Automation.PSCredential($User, $PassSecure)
		
		$ResponseData = @{}; 
		$ResponseString = Foreman_CallUrl -url $Url2Call -Method "GET" -HttpFail 401 -AutoRedirect $false -OutData $ResponseData -Credentials $Creds -ContentType $null -Headers @{Accept='*/*'}
		
		write-verbose "$($MyInvocation.InvocationName): Response received. Parsing result string!"
		$Result =  (Foreman_TranslateResponseJson $ResponseString)
		$Result | Add-Member -Type NoteProperty -Name HttpSession -Value $ResponseData.results.session;
		$Result | Add-Member -Type NoteProperty -Name Credentials -Value $Creds;
		return $Result;
	}


	Function Get-ForemanApiStatus {
		[CmdLetBinding()]
		param(
			$Session = (Get-DefaultForemanSession)
		)
		
		$URlParams = BuildForemanApiUrlParams -Session $Session -HttpMethod 'GET' -ApiMethod 'status';
		
		$ResponseString = Foreman_CallUrl @URlParams 
		return (Foreman_TranslateResponseJson $ResponseString);
	}
	
	
	Function Get-ForemanPuppetClasses {
		[CmdLetBinding()]
		param(
			$Session = (Get-DefaultForemanSession)
			,$PerPage 			= $null
			,[string]$Search 	= $null
		)
		
		$Params = @{};
		
		if($PerPage){
			$Params.add("per_page", [int]$PerPage);
		}
		
		if($Search){
			$Params.add("search", $Search);
		}
		
		$URlParams = BuildForemanApiUrlParams -Session $Session -HttpMethod 'GET' -ApiMethod 'puppetclasses' ;
		
		
		
		$ResponseString = Foreman_CallUrl @URlParams -data $Params;
		return (Foreman_TranslateResponseJson $ResponseString);
	}
	
	Function Get-ForemanHosts {
		[CmdLetBinding()]
		param(
			$Session = (Get-DefaultForemanSession)
			,$PerPage 			= $null
			,[string]$Search 	= $null
		)
		
		$Params = @{};
		
		if($PerPage){
			$Params.add("per_page", [int]$PerPage);
		}
		
		if($Search){
			$Params.add("search", $Search);
		}
		
		$URlParams = BuildForemanApiUrlParams -Session $Session -HttpMethod 'GET' -ApiMethod 'hosts';
		
		
		
		$ResponseString = Foreman_CallUrl @URlParams -data $Params;
		return (Foreman_TranslateResponseJson $ResponseString);
	}
	
	Function Set-ForemanHostPuppetClass {
		[CmdLetBinding()]
		param(
			$Session = (Get-DefaultForemanSession)
			
			,$HostId
			,[Alias('PuppetClassID')]
				$ClassID
		)
		
		$Params = @{
			#host_id = $HostId
			puppetclass_id = $ClassID
		};
		
		$URlParams = BuildForemanApiUrlParams -Session $Session -HttpMethod 'POST' -ApiMethod "hosts/$HostID/puppetclass_ids";
		
		
		$ResponseString = Foreman_CallUrl @URlParams -data $Params;
		return (Foreman_TranslateResponseJson $ResponseString);
	}
	
	Function Get-ForemanHostPuppetClass {
		[CmdLetBinding()]
		param(
			$Session = (Get-DefaultForemanSession)
			
			,$HostId
		)
		
		
		$URlParams = BuildForemanApiUrlParams -Session $Session -HttpMethod 'GET' -ApiMethod "hosts/$HostID/puppetclass_ids";
		
		
		$ResponseString = Foreman_CallUrl @URlParams;
		return (Foreman_TranslateResponseJson $ResponseString);
	}
	
	Function Remove-ForemanHostPuppetClass {
		[CmdLetBinding()]
		param(
			$Session = (Get-DefaultForemanSession)
			
			,$HostId
			,[Alias('PuppetClassID')]
				$ClassID
		)
		
		$Params = @{}
		
		$URlParams = BuildForemanApiUrlParams -Session $Session -HttpMethod 'DELETE' -ApiMethod "hosts/$HostID/puppetclass_ids/$ClassID";
		
		
		$ResponseString = Foreman_CallUrl @URlParams -data $Params;
		return (Foreman_TranslateResponseJson $ResponseString);
	}
	
	
	Function Get-ForemanLastReport {
		[CmdLetBinding()]
		param(
			$Session = (Get-DefaultForemanSession)
			
			,$HostId
		)
		
		
		$URlParams = BuildForemanApiUrlParams -Session $Session -HttpMethod 'GET' -ApiMethod "hosts/$HostID/reports/last";
		
		
		$ResponseString = Foreman_CallUrl @URlParams;
		return (Foreman_TranslateResponseJson $ResponseString);
	}
	
	Function Invoke-ForemanHostPuppetRun {
		[CmdLetBinding()]
		param(
			$Session = (Get-DefaultForemanSession)
			
			,$HostId
		)
		
		
		$URlParams = BuildForemanApiUrlParams -Session $Session -HttpMethod 'PUT' -ApiMethod "hosts/$HostID/puppetrun";
		
		
		$ResponseString = Foreman_CallUrl @URlParams;
		return (Foreman_TranslateResponseJson $ResponseString);
	}
	
	
	
	
	
# Facilities!	

	#Authenticates in a Foreman and stores in a session array!
	Function Auth-Foreman {
		[CmdLetBinding()]
		param($Url, $User, $Password, [switch]$NoSession = $false)
		
		
		#Gets a session from cache!
		$AllSessions 	= $Global:PSForeman_Storage.SESSIONS
		
		if(!$User){
			$Creds 	= Get-Credential
			$User	= $Creds.GetNetworkCredential().UserName
			$Password	= $Creds.GetNetworkCredential().Password
		}
		
		
		#Find a session with same name and url!
		$Session = $AllSessions | ? {  $_.Url -eq $Url -and $_.User -eq $User };
		
		if(!$Force -and $Session){
			write-verbose "$($MyInvocation.InvocationName): Getting from cache!"
			return $Session;
		}
		
		if(!$Session){
			write-verbose "$($MyInvocation.InvocationName): Session object dont exist. Create new!"
			$Session = New-Object PSObject -Prop @{
					Url 		= $Url
					User 		= $User
					SessionID	= $null
					Webservice	= $WebService
					RestUrl		= "$Url/api"
					Password	= $null
					NoSession	= ([bool]$NoSession)
				}
				
			$Session | Add-Member -Type ScriptMethod -Name ToString -Force -Value {
				$SessionInfo = @()

				$SessionString += @(
					"URL=$($this.Url)"
					"USER=$($this.User)";	
				)

				return $SessionString -Join " ";
			}
			
			
			$Session | Add-Member -Type ScriptMethod -Name Equals -Force -Value {
				param($Session)

				return $Session.Url -eq $this.Url -and $Session.User -eq $this.User;
			}
			
				
			$IsNewSession = $true;
		}
	
		
		if($NoSession){
			$Session.Password = $Password;
		}
		
		#Authenticates!
		$Session.SessionID = (New-ForemanSession -User $Session.User -Password $Password -Url $Session.RestUrl);
		
		if($IsNewSession){
			write-verbose "$($MyInvocation.InvocationName): Inserting on sessions cache"
			$Global:PSForeman_Storage.SESSIONS += $Session;
		}
		
		
		return $Session;
	}
	
	Function Set-DefaultForemanSession {
		[CmdLetBinding()]
		param(
			
			[Parameter(Mandatory=$True, ValueFromPipeline=$true)]
			$Session
		
		)
		
		begin {}
		process {}
		end {
			$Global:PSForeman_Storage.DEFAULT_SESSION = $Session;
		}
		
	}
	
	Function Get-DefaultForemanSession {
		
		if(@($Global:PSForeman_Storage.SESSIONS).count -eq 1){
			return @($Global:PSForeman_Storage.SESSIONS)[0];
		} else {
			return $Global:PSForeman_Storage.DEFAULT_SESSION
		}
		
	}

	Function Get-DefaultForemanSessionId {
		$d = Get-DefaultForemanSession;
		
		if($d){return $d.SessionID};
	}

	Function Get-ForemanSessions {
		return $Global:PSForeman_Storage.SESSIONS
	}
	
	Function Remove-ForemanSession {
		[CmdLetBinding()]
		param(
			
			[Parameter(Mandatory=$True, ValueFromPipeline=$true)]
			$Session
		)
		
		begin {
			$Sessions2Remove = @()
		}
		process {
			$Sessions2Remove += $Session;
		}
		end {
			$Default = $Global:PSForeman_Storage.DEFAULT_SESSION
			$Sessions2Remove | %{
				$Sess2Remove = $_;
				write-verbose "$($MyInvocation.InvocationName): Removing $Sess2Remove";

				#If is default, removes!
				if($Default -and $Default.Equals($Sess2Remove)){
					write-verbose "$($MyInvocation.InvocationName): 	Removing from default!";
					$Global:PSForeman_Storage.DEFAULT_SESSION = $null;
					$Default = $null;
				}

				<#
				if($Sess2Remove.Name){
					write-verbose "$($MyInvocation.InvocationName): 	Removing from index";
					$Global:PSForeman_Storage.SESSION_NAME.Remove($Sess2Remove.Name);
				}
				#>
				
				write-verbose "$($MyInvocation.InvocationName): 	Removing from SESSIONS list...";
				if($Global:PSForeman_Storage.SESSIONS){
					$Global:PSForeman_Storage.SESSIONS  = $Global:PSForeman_Storage.SESSIONS | ?{!$_.Equals($Sess2Remove)}
				}
			}
		}
		
	}

	Function Clean-PsForeman {
		$Global:PSForeman_Storage = @{};
	}
	
	
# Debugging

	Function Set-PsForemabDebug {
		param($state)
		
		if($state){
			write-host "Enabling debug options..."
			$Global:PSForeman_Storage.DEBUG_OPTIONS.ENABLED = $true
		} else {
			write-host "Disabling debug options..."
			$Global:PSForeman_Storage.DEBUG_OPTIONS.ENABLED = $false
		}
		
	}

	Function  Get-PsForemabDebug {
		return $Global:PSForeman_Storage.DEBUG_OPTIONS
	}
	
	
	
	
	
	
	