from lib.Offer import Offer
from lib.Log import Log
from lib.Constants import  Constants
import requests, time, os, sys, json
from requests.models import Response
from datetime import datetime
from prettytable import PrettyTable
from urllib.parse import unquote, urlparse, parse_qs
import base64, hashlib, hmac, gzip, secrets
import pyaes
from argparse import ArgumentParser, Namespace
from pbkdf2 import PBKDF2

try:
  from twilio.rest import Client
except:
  pass

class FlexUnlimited:
  def __init__(self) -> None:
    # Load all arguments pass to script
    self.__load_arguments()
    # Make new factory client for twilio
    self.__factoryClientTwilio()
    # Login into AmazonFlex
    self.__registerAccount()

    self.__retryCount = 0
    self.__rate_limit_number = 1
    self.__acceptedOffers = []
    self.__startTimestamp = time.time()
    self.__requestHeaders = Constants.allHeaders.get("FlexCapacityRequest")
    self.session = requests.Session()
    self.session.proxies.update(self.proxies)
  
    self.__requestHeaders["x-amz-access-token"] = self.accessToken
    self.__requestHeaders["X-Amz-Date"] = FlexUnlimited.__getAmzDate()
    self.serviceAreaIds = self.__getEligibleServiceAreas()
    self.__offersRequestBody = {
      "apiVersion": "V2",
      "filters": {
        "serviceAreaFilter": self.desiredWarehouses,
        "timeFilter": {"endTime": self.desiredEndTime, "startTime": self.desiredStartTime}
      },
      "serviceAreaIds": self.serviceAreaIds
    }

  def __set_arguments(self) -> Namespace: 
    parser = ArgumentParser()
    parser.add_argument('--username', help='Username of AmazonFlex', type=str)
    parser.add_argument('--password', help='Password of AmazonFlex', type=str)

    parser.add_argument('--desiredWarehouses', help='List of warehouse ids', nargs='*', type=str)

    parser.add_argument('--minBlockRate', help='Minimum block rate', type=int)
    parser.add_argument('--minPayRatePerHour', help='Minimum hourly pay rate', type=int)

    parser.add_argument('--arrivalBuffer', help='Arrival buffer in minutes', type=int)
    parser.add_argument('--desiredStartTime', help='Start time in military time', type=str)
    parser.add_argument('--desiredEndTime', help='End time in military time', type=str)
    parser.add_argument('--desiredWeekdays', help='Sets delay in between getOffers requests', nargs='*', type=str)

    parser.add_argument('--retryLimit', help='Number of jobs retrieval requests to perform', type=int)
    parser.add_argument('--refreshInterval', help='Time interval to resume the search', type=int)
  
    parser.add_argument('--refreshToken', help='Refresh Token', type=str)
    parser.add_argument('--accessToken', help='Access Token', type=str)

    parser.add_argument('--proxyUrl', help='Proxy url', type=str)
    parser.add_argument('--proxyUserame', help='Proxy username', type=str)
    parser.add_argument('--proxyPassword', help='Proxy password', type=str)

    # Information about the device that will establish the connection to AWS Flex. 
    parser.add_argument('--appName', help='Application name')
    parser.add_argument('--appVersion', help='Application verison')
    parser.add_argument('--deviceName', help='Device name')
    parser.add_argument('--manufacturer', help='Manufacturer')
    parser.add_argument('--osVersion', help='OS version')

    # Twilio settings
    parser.add_argument('--twilioFromNumber', help='Twilio from number', type=str)
    parser.add_argument('--twilioToNumber', help='Twilio to number', type=str)
    parser.add_argument('--twilioAcctSid', help='Twilio acct sid', type=str)
    parser.add_argument('--twilioAuthToken', help='Twilio auth token', type=str)

    return parser.parse_args()

  def __load_arguments(self) -> None: 
    args = self.__set_arguments()
    
    self.username = args.username
    self.password = args.password

    self.desiredWarehouses = args.desiredWarehouses

    self.minBlockRate = args.minBlockRate
    self.minPayRatePerHour = args.minPayRatePerHour

    self.arrivalBuffer = args.arrivalBuffer
    self.desiredStartTime = args.desiredStartTime
    self.desiredEndTime = args.desiredEndTime
    self.desiredWeekdays = set()
    self.__setDesiredWeekdays(args.desiredWeekdays)

    self.retryLimit = args.retryLimit
    self.refreshInterval = args.refreshInterval

    self.refreshToken = args.refreshToken
    self.accessToken = args.accessToken

    self.proxies = Constants.getProxies(args.proxyUrl, args.proxies, args.proxyPassword)

    self.appName = args.appName
    self.appVersion = args.appVersion
    self.deviceName = args.deviceName
    self.manufacturer = args.manufacturer
    self.osVersion = args.osVersion
    
    self.twilioFromNumber = args.twilioFromNumber
    self.twilioToNumber = args.twilioToNumber
    self.twilioAcctSid = args.twilioAcctSid
    self.twilioAuthToken = args.twilioAuthToken

  def __factoryClientTwilio():
    self.twilioClient = None

    if self.twilioAcctSid == "":
      return 

    if self.twilioAuthToken == "":
      return 

    if self.twilioFromNumber == "":
      return 

    if self.twilioToNumber == "":
      return 

    self.twilioClient = Client(self.twilioAcctSid, self.twilioAuthToken)

    
  def __setDesiredWeekdays(self, desiredWeekdays):
    weekdayMap = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}
    if len(desiredWeekdays) == 0:
      self.desiredWeekdays = None
    else:
      for day in desiredWeekdays:
        dayAbbreviated = day[:3].lower()
        if dayAbbreviated not in weekdayMap:
          print("Weekday '" + day + "' is misspelled. Please correct config.json file and restart program.")
          exit()
        self.desiredWeekdays.add(weekdayMap[dayAbbreviated])
      if len(self.desiredWeekdays) == 7:
        self.desiredWeekdays = None

  def __registerAccount(self):
    if self.refreshToken != "":
      return

    print("Link: " + Constants.get("RegisterAccount"))
    maplanding_url = input("Open the previous link (make sure to copy the entire link) in a browser, sign in, and enter the entire resulting URL here:\n")
    parsed_query = parse_qs(urlparse(maplanding_url).query)
    reg_access_token = unquote(parsed_query['openid.oa2.access_token'][0])
    device_id = secrets.token_hex(16)

    amazon_reg_data = {
      "auth_data": {
        "access_token": reg_access_token
      },
      "cookies": {
        "domain": ".amazon.com",
        "website_cookies": []
      },
      "device_metadata": {
        "android_id": "52aee8aecab31ee3",
        "device_os_family": "android",
        "device_serial": device_id,
        "device_type": "A1MPSLFC7L5AFK",
        "mac_address": secrets.token_hex(64).upper(),
        "manufacturer": self.manufacturer,
        "model": self.deviceName,
        "os_version": "30",
        "product": self.deviceName
      },
      "registration_data": {
        "app_name": self.appName,
        "app_version": self.appVersion,
        "device_model": self.deviceName,
        "device_serial": device_id,
        "device_type": "A1MPSLFC7L5AFK",
        "domain": "Device",
        "os_version": self.osVersion,
        "software_version": "130050002"
      },
      "requested_extensions": [
        "device_info",
        "customer_info"
      ],
      "requested_token_type": [
        "bearer",
        "mac_dms",
        "store_authentication_cookie",
        "website_cookies"
      ],
      "user_context_map": {
        "frc": self.__generate_frc(device_id)
      }
    }

    res = self.session.post(
                Constants.routes.get("GetAuthToken"), 
                headers=Constants.allHeaders.get("AmazonApiLogin"), 
                json=amazon_reg_data, 
                verify=True)

    if res.status_code != 200:
        print("login failed")
        exit(1)

    res = res.json()
    tokens = res['response']['success']['tokens']['bearer']

    self.accessToken = tokens['access_token']
    self.refreshToken = tokens['refresh_token']

    print("Displaying refresh token in case config file fails to save tokens.")
    print("If it fails, copy the refresh token into the config file manually.")
    print("Refresh token: " + self.refreshToken)

    try:
      with open("config.json", "r+") as configFile:
        config = json.load(configFile)
        config["accessToken"] = self.accessToken
        config["refreshToken"] = self.refreshToken
        configFile.seek(0)
        json.dump(config, configFile, indent=2)
        configFile.truncate()
    except KeyError as nullKey:
      Log.error(f'{nullKey} was not set. Please setup FlexUnlimited as described in the README.')
      sys.exit()
    except FileNotFoundError:
      Log.error("Config file not found. Ensure a properly formatted 'config.json' file exists in the root directory.")
      sys.exit()
    print("registration successful")

  @staticmethod
  def __generate_frc(device_id):
    """
    Helper method for the register function. Generates user context map.
    """
    cookies = json.dumps({
      "ApplicationName": self.appName,
      "ApplicationVersion": self.appVersion,
      "DeviceLanguage": "en",
      "DeviceName": self.deviceName,
      "DeviceOSVersion": self.osVersion,
      "IpAddress": requests.get('https://api.ipify.org').text,
      "ScreenHeightPixels": "1920",
      "ScreenWidthPixels": "1280",
      "TimeZone": "00:00",
    })
    compressed = gzip.compress(cookies.encode())
    key = PBKDF2(device_id, b"AES/CBC/PKCS7Padding").read(32)
    iv = secrets.token_bytes(16)
    encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(key, iv=iv))
    ciphertext = encrypter.feed(compressed)
    ciphertext += encrypter.feed()
    hmac_ = hmac.new(PBKDF2(device_id, b"HmacSHA256").read(32), iv + ciphertext, hashlib.sha256).digest()
    return base64.b64encode(b"\0" + hmac_[:8] + iv + ciphertext).decode()

  def __getFlexAccessToken(self):
    data = {
      "app_name": self.appName,
      "app_version": self.appVersion,
      "source_token_type": "refresh_token",
      "source_token": self.refreshToken,
      "requested_token_type": "access_token",
    }
    request = self.session.post(
                    Constants.routes.get("RequestNewAccessToken"), 
                    headers=Constants.allHeaders.get("FlexAccessToken"),
                    json=data)
    res = request.json()
    self.accessToken = res['access_token']

    try:
      with open("config.json", "r+") as configFile:
        config = json.load(configFile)
        config["accessToken"] = self.accessToken
        configFile.seek(0)
        json.dump(config, configFile, indent=2)
        configFile.truncate()
    except KeyError as nullKey:
      Log.error(f'{nullKey} was not set. Please setup FlexUnlimited as described in the README.')
      sys.exit()
    except FileNotFoundError:
      Log.error("Config file not found. Ensure a properly formatted 'config.json' file exists in the root directory.")
      sys.exit()
    self.__requestHeaders["x-amz-access-token"] = self.accessToken

  def __getFlexRequestAuthToken(self) -> str:
    """
        Get authorization token for Flex Capacity requests
        Returns:
        An access token as a string
        """
    payload = {
      "requested_extensions": ["device_info", "customer_info"],
      "cookies": {
        "website_cookies": [],
        "domain": ".amazon.com"
      },
      "registration_data": {
        "domain": "Device",
        "app_version": "0.0",
        "device_type": "A3NWHXTQ4EBCZS",
        "os_version": "15.2",
        "device_serial": "0000000000000000",
        "device_model": "iPhone",
        "app_name": "Amazon Flex",
        "software_version": "1"
      },
      "auth_data": {
        "user_id_password": {
          "user_id": self.username,
          "password": self.password
        }
      },
      "user_context_map": {
        "frc": ""},
      "requested_token_type": ["bearer", "mac_dms", "website_cookies"]
    }
    try:
      request = self.session.post(
                        Constants.routes.get("GetAuthToken"),
                        headers=Constants.allHeaders.get("AmazonApiRequest"), 
                        json=payload)
      response = request.json()
      return response.get("response").get("success").get("tokens").get("bearer").get("access_token")
    except Exception as e:
      twoStepVerificationChallengeUrl = self.__getTwoStepVerificationChallengeUrl(response)
      print("Unable to authenticate to Amazon Flex.")
      print(f"\nPlease try completing the two step verification challenge at \033[1m{twoStepVerificationChallengeUrl}\033[0m . Then try again.")
      print("\nIf you already completed the two step verification, please check your Amazon Flex username and password in the config file and try again.")
      sys.exit()

  """
  Parse the verification challenge code unique to the user from the failed login attempt and return the url where they can complete the two step verification.
  """
  def __getTwoStepVerificationChallengeUrl(self, challengeRequest: Response) -> str:
    return Constants.getTwoStepVerificationChallengeUrl(
        challengeRequest
                .get("response")
                .get("challenge")
                .get("uri")
                .split("?")[1]
                .split("=")[1]
    )

  @staticmethod
  def __getAmzDate() -> str:
    """
        Returns Amazon formatted timestamp as string
        """
    return datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')

  def __getEligibleServiceAreas(self):
    self.__requestHeaders["X-Amz-Date"] = FlexUnlimited.__getAmzDate()
    response = self.session.get(
                      Constants.routes.get("GetEligibleServiceAreas"),
                      headers=self.__requestHeaders)
    if response.status_code == 403:
      self.__getFlexAccessToken()
      response = self.session.get(
                        Constants.routes.get("GetEligibleServiceAreas"),
                        headers=self.__requestHeaders)
    return response.json().get("serviceAreaIds")

  def getAllServiceAreas(self):
    self.__requestHeaders["X-Amz-Date"] = FlexUnlimited.__getAmzDate()
    response = self.session.get(
                      Constants.routes.get("GetOfferFiltersOptions"),
                      headers=self.__requestHeaders)
    if response.status_code == 403:
      self.__getFlexAccessToken()
      response = self.session.get(
                        Constants.routes.get("GetOfferFiltersOptions"),
                        headers=self.__requestHeaders)

    serviceAreaPoolList = response.json().get("serviceAreaPoolList")
    serviceAreasTable = PrettyTable()
    serviceAreasTable.field_names = ["Service Area Name", "Service Area ID"]
    for serviceArea in serviceAreaPoolList:
      serviceAreasTable.add_row([serviceArea["serviceAreaName"], serviceArea["serviceAreaId"]])
    return serviceAreasTable

  def __getOffers(self) -> Response:
    """
    Get job offers.
    
    Returns:
    Offers response object
    """
    response = self.session.post(
                      Constants.routes.get("GetOffers"),
                      headers=self.__requestHeaders,
                      json=self.__offersRequestBody)

    if response.status_code == 403:
      self.__getFlexAccessToken()
      response = self.session.post(
                        Constants.routes.get("GetOffers"),
                        headers=self.__requestHeaders,
                        json=self.__offersRequestBody)

    return response

  def __acceptOffer(self, offer: Offer):
    self.__requestHeaders["X-Amz-Date"] = self.__getAmzDate()

    request = self.session.post(
                      Constants.routes.get("AcceptOffer"),
                      headers=self.__requestHeaders,
                      json={"offerId": offer.id})

    if request.status_code == 403:
      self.__getFlexAccessToken()
      request = self.session.post(
                        Constants.routes.get("AcceptOffer"),
                        headers=self.__requestHeaders,
                        json={"offerId": offer.id})

    if request.status_code == 200:
      self.__acceptedOffers.append(offer)
      if self.twilioClient is not None:
        self.twilioClient.messages.create(
                            to=self.twilioToNumber,
                            from_=self.twilioFromNumber,
                            body=offer.toString())
      Log.info(f"Successfully accepted an offer.")
    else:
      Log.error(f"Unable to accept an offer. Request returned status code {request.status_code}")

  def __processOffer(self, offer: Offer):
    if offer.hidden:
      return
      
    if self.desiredWeekdays:
      if offer.weekday not in self.desiredWeekdays:
        return

    if self.minBlockRate:
      if offer.blockRate < self.minBlockRate:
        return

    if self.minPayRatePerHour:
      if offer.ratePerHour < self.minPayRatePerHour:
        return

    if self.arrivalBuffer:
      deltaTime = (offer.startTime - datetime.now()).seconds / 60
      if deltaTime < self.arrivalBuffer:
        return

    self.__acceptOffer(offer)

  def run(self):
    Log.info("Starting job search...")
    while self.__retryCount < self.retryLimit:
      if not self.__retryCount % 50:
        print(self.__retryCount, 'requests attempted\n\n')

      offersResponse = self.__getOffers()
      if offersResponse.status_code == 200:
        currentOffers = offersResponse.json().get("offerList")
        currentOffers.sort(key=lambda pay: int(pay['rateInfo']['priceAmount']),
                           reverse=True)
        for offer in currentOffers:
          offerResponseObject = Offer(offerResponseObject=offer)
          self.__processOffer(offerResponseObject)
        self.__retryCount += 1
      elif offersResponse.status_code == 400:
        minutes_to_wait = 30 * self.__rate_limit_number
        Log.info("Rate limit reached. Waiting for " + str(minutes_to_wait) + " minutes.")
        time.sleep(minutes_to_wait * 60)
        if self.__rate_limit_number < 4:
          self.__rate_limit_number += 1
        else:
          self.__rate_limit_number = 1
        Log.info("Resuming search.")
      else:
        Log.error(offersResponse.json())
        break
      time.sleep(self.refreshInterval)
    Log.info("Job search cycle ending...")
    Log.info(f"Accepted {len(self.__acceptedOffers)} offers in {time.time() - self.__startTimestamp} seconds")
