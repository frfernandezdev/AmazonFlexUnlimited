class Constants:
  allHeaders = {
    "AmazonApiRequest": {
      "x-amzn-identity-auth-domain": "api.amazon.com",
      "User-Agent": "AmazonWebView/Amazon Flex/0.0/iOS/15.2/iPhone"
    },
    "AmazonApiLogin": {
      "Content-Type": "application/json",
      "Accept-Charset": "utf-8",
      "x-amzn-identity-auth-domain": "api.amazon.com",
      "Connection": "keep-alive",
      "Accept": "*/*",
      "Accept-Language": "en-US"
    },
    "FlexCapacityRequest": {
      "Accept": "application/json",
      "x-amz-access-token": None,
      "Authorization": "RABBIT3-HMAC-SHA256 SignedHeaders=x-amz-access-token;x-amz-date, "
                       "Signature=82e65bd06035d5bba38c733ac9c48559c52c7574fb7fa1d37178e83c712483c0",
      "X-Amz-Date": None,
      "Accept-Encoding": "gzip, deflate, br",
      "x-flex-instance-id": "BEEBE19A-FF23-47C5-B1D2-21507C831580",
      "Accept-Language": "en-US",
      "Content-Type": "application/json",
      "User-Agent": "iOS/16.1 (iPhone Darwin) Model/iPhone Platform/iPhone14,2 RabbitiOS/2.112.2",
      "Connection": "keep-alive",
      "Cookie": 'session-id=147-7403990-6925948; session-id-time=2082787201l; '
                'session-token=1mGSyTQU1jEQgpSB8uEn6FFHZ1iBcFpe9V7LTPGa3GV3sWf4bgscBoRKGmZb3TQICu7PSK5q23y3o4zYYhP'
                '/BNB5kHAfMvWcqFPv/0AV7dI7desGjE78ZIh+N9Jv0KV8c3H/Xyh0OOhftvJQ5eASleRuTG5+TQIZxJRMJRp84H5Z+YI'
                '+IhWErPdxUVu8ztJiHaxn05esQRqnP83ZPxwNhA4uwaxrT2Xm; '
                'at-main="Atza|IwEBIB4i78dwxnHVELVFRFxlWdNNXzFreM2pXeOHsic9Xo54CXhW0m5juyNgKyCL6KT_9bHrQP7VUAIkxw'
                '-nT2JH12KlOuYp6nbdv-y6cDbV5kjPhvFntPyvBEYcl405QleSzBtH_HUkMtXcxeFYygt8l-KlUA8-JfEKHGD14'
                '-oluobSCd2UdlfRNROpfRJkICzo5NSijF6hXG4Ta3wjX56bkE9X014ZnVpeD5uSi8pGrLhBB85o4PKh55ELQh0fwuGIJyBcyWSpGPZb5'
                'uVODSsXQXogw7HCFEoRnZYSvR_t7GF5hm_78TluPKUoYzvw4EVfJzU"; '
                'sess-at-main="jONjae0aLTmT+yqJV5QC+PC1yiAdolAm4zRrUlcnufM="; '
                'ubid-main=131-1001797-1551209; '
                'x-main="ur180BSwQksvu@cBWH@IQejqHw6ZYkMDKkwbdOwJvEeVZWlh15tnxZdleqfq9qO0"'
    },
    "FlexAccessToken": {
      "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 10; Pixel 2 Build/OPM1.171019.021)",
      "x-amzn-identity-auth-domain": "api.amazon.com",
    }
  }
  routes = {
    "GetOffers": "https://flex-capacity-na.amazon.com/GetOffersForProviderPost",
    "AcceptOffer": "https://flex-capacity-na.amazon.com/AcceptOffer",
    "GetAuthToken": "https://api.amazon.com/auth/register",
    "RequestNewAccessToken": "https://api.amazon.com/auth/token",
    "ForfeitOffer": "https://flex-capacity-na.amazon.com/schedule/blocks/",
    "GetEligibleServiceAreas": "https://flex-capacity-na.amazon.com/eligibleServiceAreas",
    "GetOfferFiltersOptions": "https://flex-capacity-na.amazon.com/getOfferFiltersOptions",
    "RegisterAccount":
        "https://www.amazon.com/ap/signin?ie=UTF8&clientContext=134-9172090-0857541&openid.pape.max_auth_age=0&use_global_authentication=false&accountStatusPolicy=P1&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&use_audio_captcha=false&language=en_US&pageId=amzn_device_na&arb=97b4a0fe-13b8-45fd-b405-ae94b0fec45b&openid.return_to=https%3A%2F%2Fwww.amazon.com%2Fap%2Fmaplanding&openid.assoc_handle=amzn_device_na&openid.oa2.response_type=token&openid.mode=checkid_setup&openid.ns.pape=http%3A%2F%2Fspecs.openid.net%2Fextensions%2Fpape%2F1.0&openid.ns.oa2=http%3A%2F%2Fwww.amazon.com%2Fap%2Fext%2Foauth%2F2&openid.oa2.scope=device_auth_access&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&disableLoginPrepopulate=0&openid.oa2.client_id=device%3A32663430323338643639356262653236326265346136356131376439616135392341314d50534c4643374c3541464b&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0"
  }

  @staticmethod
  def getTwoStepVerificationChallengeUrl(verificationChallengeCode: str) -> str: 
    return "https://www.amazon.com/ap/challenge?openid.return_to=https://www.amazon.com/ap/maplanding&openid.oa2.code_challenge_method=S256&openid.assoc_handle=amzn_device_ios_us&pageId=amzn_device_ios_light&accountStatusPolicy=P1&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select&openid.mode=checkid_setup&openid.identity=http://specs.openid.net/auth/2.0/identifier_select&openid.ns.oa2=http://www.amazon.com/ap/ext/oauth/2&openid.oa2.client_id=device:30324244334531423246314134354635394236443142424234413744443936452341334e5748585451344542435a53&language=en_US&openid.ns.pape=http://specs.openid.net/extensions/pape/1.0&openid.oa2.code_challenge=n76GtDRiGSvq-Bhrez9x0CypsZFB_7eLfEDy_qZtqFk&openid.oa2.scope=device_auth_access&openid.ns=http://specs.openid.net/auth/2.0&openid.pape.max_auth_age=0&openid.oa2.response_type=code" + f"&arb={verificationChallengeCode}"

  @staticmethod
  def getProxies(url: str, username: str, password: str) -> dict:
    return {
      'http': f'http://{username}:{password}@{url}',
      'https': f'http://{username}:{password}@{url}'
    }
