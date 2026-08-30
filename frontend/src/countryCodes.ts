// ISO 3166-1 numeric code (as string in world-atlas topojson) -> alpha-2 code.
// Covers all 177 countries in world-atlas@2/countries-110m.json.
const NUMERIC_TO_ALPHA2: Record<string, string> = {
  '004': 'AF', '008': 'AL', '010': 'AQ', '012': 'DZ', '024': 'AO', '031': 'AZ',
  '032': 'AR', '036': 'AU', '040': 'AT', '044': 'BS', '050': 'BD', '051': 'AM',
  '056': 'BE', '064': 'BT', '068': 'BO', '070': 'BA', '072': 'BW', '076': 'BR',
  '084': 'BZ', '090': 'SB', '096': 'BN', '100': 'BG', '104': 'MM', '108': 'BI',
  '112': 'BY', '116': 'KH', '120': 'CM', '124': 'CA', '140': 'CF', '144': 'LK',
  '148': 'TD', '152': 'CL', '156': 'CN', '158': 'TW', '170': 'CO', '178': 'CG',
  '180': 'CD', '188': 'CR', '191': 'HR', '192': 'CU', '196': 'CY', '203': 'CZ',
  '204': 'BJ', '208': 'DK', '214': 'DO', '218': 'EC', '222': 'SV', '226': 'GQ',
  '231': 'ET', '232': 'ER', '233': 'EE', '238': 'FK', '242': 'FJ', '246': 'FI',
  '250': 'FR', '260': 'TF', '262': 'DJ', '266': 'GA', '268': 'GE', '270': 'GM',
  '275': 'PS', '276': 'DE', '288': 'GH', '300': 'GR', '304': 'GL', '320': 'GT',
  '324': 'GN', '328': 'GY', '332': 'HT', '340': 'HN', '348': 'HU', '352': 'IS',
  '356': 'IN', '360': 'ID', '364': 'IR', '368': 'IQ', '372': 'IE', '376': 'IL',
  '380': 'IT', '384': 'CI', '388': 'JM', '392': 'JP', '398': 'KZ', '400': 'JO',
  '404': 'KE', '408': 'KP', '410': 'KR', '414': 'KW', '417': 'KG', '418': 'LA',
  '422': 'LB', '426': 'LS', '428': 'LV', '430': 'LR', '434': 'LY', '440': 'LT',
  '442': 'LU', '450': 'MG', '454': 'MW', '458': 'MY', '466': 'ML', '478': 'MR',
  '484': 'MX', '496': 'MN', '498': 'MD', '499': 'ME', '504': 'MA', '508': 'MZ',
  '512': 'OM', '516': 'NA', '524': 'NP', '528': 'NL', '540': 'NC', '548': 'VU',
  '554': 'NZ', '558': 'NI', '562': 'NE', '566': 'NG', '578': 'NO', '586': 'PK',
  '591': 'PA', '598': 'PG', '600': 'PY', '604': 'PE', '608': 'PH', '616': 'PL',
  '620': 'PT', '624': 'GW', '626': 'TL', '630': 'PR', '634': 'QA', '642': 'RO',
  '643': 'RU', '646': 'RW', '682': 'SA', '686': 'SN', '688': 'RS', '694': 'SL',
  '703': 'SK', '704': 'VN', '705': 'SI', '706': 'SO', '710': 'ZA', '716': 'ZW',
  '724': 'ES', '728': 'SS', '729': 'SD', '732': 'EH', '740': 'SR', '748': 'SZ',
  '752': 'SE', '756': 'CH', '760': 'SY', '762': 'TJ', '764': 'TH', '768': 'TG',
  '780': 'TT', '784': 'AE', '788': 'TN', '792': 'TR', '795': 'TM', '800': 'UG',
  '804': 'UA', '807': 'MK', '818': 'EG', '826': 'GB', '834': 'TZ', '840': 'US',
  '854': 'BF', '858': 'UY', '860': 'UZ', '862': 'VE', '887': 'YE', '894': 'ZM',
}

export function numericToAlpha2(id: string | number | undefined): string | undefined {
  if (id == null) return undefined
  return NUMERIC_TO_ALPHA2[String(id).padStart(3, '0')] || NUMERIC_TO_ALPHA2[String(id)]
}

// ISO 3166-1 alpha-2 code -> full country name.
// Covers all 177 countries in world-atlas@2/countries-110m.json.
const ALPHA2_TO_NAME: Record<string, string> = {
  AF: 'Afghanistan', AL: 'Albania', AQ: 'Antarctica', DZ: 'Algeria', AO: 'Angola',
  AZ: 'Azerbaijan', AR: 'Argentina', AU: 'Australia', AT: 'Austria', BS: 'Bahamas',
  BD: 'Bangladesh', AM: 'Armenia', BE: 'Belgium', BT: 'Bhutan', BO: 'Bolivia',
  BA: 'Bosnia and Herzegovina', BW: 'Botswana', BR: 'Brazil', BZ: 'Belize',
  SB: 'Solomon Islands', BN: 'Brunei Darussalam', BG: 'Bulgaria', MM: 'Myanmar',
  BI: 'Burundi', BY: 'Belarus', KH: 'Cambodia', CM: 'Cameroon', CA: 'Canada',
  CF: 'Central African Republic', LK: 'Sri Lanka', TD: 'Chad', CL: 'Chile',
  CN: 'China', TW: 'Taiwan', CO: 'Colombia', CG: 'Congo', CD: 'Democratic Republic of the Congo',
  CR: 'Costa Rica', HR: 'Croatia', CU: 'Cuba', CY: 'Cyprus', CZ: 'Czechia',
  BJ: 'Benin', DK: 'Denmark', DO: 'Dominican Republic', EC: 'Ecuador', SV: 'El Salvador',
  GQ: 'Equatorial Guinea', ET: 'Ethiopia', ER: 'Eritrea', EE: 'Estonia', FK: 'Falkland Islands (Malvinas)',
  FJ: 'Fiji', FI: 'Finland', FR: 'France', TF: 'French Southern Territories', DJ: 'Djibouti',
  GA: 'Gabon', GE: 'Georgia', GM: 'Gambia', PS: 'Palestine, State of', DE: 'Germany',
  GH: 'Ghana', GR: 'Greece', GL: 'Greenland', GT: 'Guatemala', GN: 'Guinea',
  GY: 'Guyana', HT: 'Haiti', HN: 'Honduras', HU: 'Hungary', IS: 'Iceland',
  IN: 'India', ID: 'Indonesia', IR: 'Iran', IQ: 'Iraq', IE: 'Ireland',
  IL: 'Israel', IT: 'Italy', CI: "Côte d'Ivoire", JM: 'Jamaica', JP: 'Japan',
  KZ: 'Kazakhstan', JO: 'Jordan', KE: 'Kenya', KP: "Korea (Democratic People's Republic of)", KR: 'Korea, Republic of',
  KW: 'Kuwait', KG: 'Kyrgyzstan', LA: "Lao People's Democratic Republic", LB: 'Lebanon', LS: 'Lesotho',
  LV: 'Latvia', LR: 'Liberia', LY: 'Libya', LT: 'Lithuania', LU: 'Luxembourg',
  MG: 'Madagascar', MW: 'Malawi', MY: 'Malaysia', ML: 'Mali', MR: 'Mauritania',
  MX: 'Mexico', MN: 'Mongolia', MD: 'Moldova', ME: 'Montenegro', MA: 'Morocco',
  MZ: 'Mozambique', OM: 'Oman', NA: 'Namibia', NP: 'Nepal', NL: 'Netherlands',
  NC: 'New Caledonia', VU: 'Vanuatu', NZ: 'New Zealand', NI: 'Nicaragua', NE: 'Niger',
  NG: 'Nigeria', NO: 'Norway', PK: 'Pakistan', PA: 'Panama', PG: 'Papua New Guinea',
  PY: 'Paraguay', PE: 'Peru', PH: 'Philippines', PL: 'Poland', PT: 'Portugal',
  GW: 'Guinea-Bissau', TL: 'Timor-Leste', PR: 'Puerto Rico', QA: 'Qatar', RO: 'Romania',
  RU: 'Russian Federation', RW: 'Rwanda', SA: 'Saudi Arabia', SN: 'Senegal', RS: 'Serbia',
  SL: 'Sierra Leone', SK: 'Slovakia', VN: 'Viet Nam', SI: 'Slovenia', SO: 'Somalia',
  ZA: 'South Africa', ZW: 'Zimbabwe', ES: 'Spain', SS: 'South Sudan', SD: 'Sudan',
  EH: 'Western Sahara', SR: 'Suriname', SZ: 'Eswatini', SE: 'Sweden', CH: 'Switzerland',
  SY: 'Syrian Arab Republic', TJ: 'Tajikistan', TH: 'Thailand', TG: 'Togo', TT: 'Trinidad and Tobago',
  AE: 'United Arab Emirates', TN: 'Tunisia', TR: 'Türkiye', TM: 'Turkmenistan', UG: 'Uganda',
  UA: 'Ukraine', MK: 'North Macedonia', EG: 'Egypt', GB: 'United Kingdom', TZ: 'Tanzania',
  US: 'United States of America', BF: 'Burkina Faso', UY: 'Uruguay', UZ: 'Uzbekistan',
  VE: 'Venezuela', YE: 'Yemen', ZM: 'Zambia',
}

export function alpha2ToName(code: string | undefined): string | undefined {
  if (code == null) return undefined
  return ALPHA2_TO_NAME[code.toUpperCase()]
}
