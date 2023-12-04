import sys
from argparse import (
    ArgumentParser,
    Namespace,
)
from lib.FlexUnlimited import (
    FlexUnlimited,
)

if __name__ == "__main__":
    print("***Amazon Flex Unlimited v2*** \n")

    parser = ArgumentParser()
    parser.add_argument(
        "--username",
        help="Username of AmazonFlex",
        type=str,
    )
    parser.add_argument(
        "--password",
        help="Password of AmazonFlex",
        type=str,
    )

    parser.add_argument(
        "--desiredWarehouses",
        help="List of warehouse ids",
        nargs="*",
        type=str,
    )

    parser.add_argument(
        "--minBlockRate",
        help="Minimum block rate",
        type=int,
    )
    parser.add_argument(
        "--minPayRatePerHour",
        help="Minimum hourly pay rate",
        type=int,
    )

    parser.add_argument(
        "--arrivalBuffer",
        help="Arrival buffer in minutes",
        type=int,
    )
    parser.add_argument(
        "--desiredStartTime",
        help="Start time in military time",
        type=str,
    )
    parser.add_argument(
        "--desiredEndTime",
        help="End time in military time",
        type=str,
    )
    parser.add_argument(
        "--desiredWeekdays",
        help="Sets delay in between getOffers requests",
        nargs="*",
        type=str,
        default=set()
    )

    parser.add_argument(
        "--retryLimit",
        help="Number of jobs retrieval requests to perform",
        type=int,
    )
    parser.add_argument(
        "--refreshInterval",
        help="Time interval to resume the search",
        type=int,
    )

    parser.add_argument(
        "--refreshToken",
        help="Refresh Token",
        type=str,
    )
    parser.add_argument(
        "--accessToken",
        help="Access Token",
        type=str,
    )

    parser.add_argument(
        "--proxyUrl",
        help="Proxy url",
        type=str,
    )
    parser.add_argument(
        "--proxyUserame",
        help="Proxy username",
        type=str,
    )
    parser.add_argument(
        "--proxyPassword",
        help="Proxy password",
        type=str,
    )

    # Information about the device that will establish the connection to AWS Flex.
    parser.add_argument("--appName", help="Application name", type=str)
    parser.add_argument("--appVersion", help="Application verison", type=str)
    parser.add_argument("--deviceName", help="Device name", type=str)
    parser.add_argument("--manufacturer", help="Manufacturer", type=str)
    parser.add_argument("--osVersion", help="OS version", type=str)

    # Twilio settings
    parser.add_argument(
        "--twilioFromNumber",
        help="Twilio from number",
        type=str,
    )
    parser.add_argument(
        "--twilioToNumber",
        help="Twilio to number",
        type=str,
    )
    parser.add_argument(
        "--twilioAcctSid",
        help="Twilio acct sid",
        type=str,
    )
    parser.add_argument(
        "--twilioAuthToken",
        help="Twilio auth token",
        type=str,
    )

    parser.add_argument(
        "--getAllServiceAreas",
        "-w",
        dest="getAllServiceAreas",
        action="store_true",
        help="Get all service areas",
    )
    parser.add_argument(
        "--getOffers",
        "-o",
        dest="getOffers",
        action="store_true",
        help="Get all job offers",
    )
    args = parser.parse_args()

    flexUnlimited = FlexUnlimited(
        username=args.username,
        password=args.password,
        desiredWarehouses=args.desiredWarehouses,
        minBlockRate=args.minBlockRate,
        minPayRatePerHour=args.minPayRatePerHour,
        arrivalBuffer=args.arrivalBuffer,
        desiredStartTime=args.desiredStartTime,
        desiredEndTime=args.desiredEndTime,
        desiredWeekdays=args.desiredWeekdays,
        retryLimit=args.retryLimit,
        refreshInterval=args.refreshInterval,
        refreshToken=args.refreshToken,
        accessToken=args.accessToken,
        proxyUrl=args.proxyUrl,
        proxyUserame=args.proxyUserame,
        proxyPassword=args.proxyPassword,
        appName=args.appName,
        appVersion=args.appVersion,
        deviceName=args.deviceName,
        manufacturer=args.manufacturer,
        osVersion=args.osVersion,
        twilioFromNumber=args.twilioFromNumber,
        twilioToNumber=args.twilioToNumber,
        twilioAcctSid=args.twilioAcctSid,
        twilioAuthToken=args.twilioAuthToken,
    )
    if args.getAllServiceAreas:
        print("\n Your service area options:")
        print(flexUnlimited.getAllServiceAreas())
    elif args.getOffers:
        print("\n Your job offers:")
        print(flexUnlimited.getOffers())
    else:
        flexUnlimited.run()
