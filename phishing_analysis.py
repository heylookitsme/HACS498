from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
otx = OTXv2("6bf1115fc257d930fcb89416a03572f26a2bf0f3a02f94a7c6e08078ae4fdf42")
# Get all the indicators associated with a pulse
indicators = otx.get_pulse_indicators("pulse_id")
for indicator in indicators:
    print(indicator["indicator"] + indicator["type"])
# Get everything OTX knows about google.com
otx.get_indicator_details_full(IndicatorTypes.DOMAIN, "google.com")