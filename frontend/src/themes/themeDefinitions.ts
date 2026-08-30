export interface ThemeColors {
  // Backgrounds
  bgPrimary: string
  bgSecondary: string
  bgTertiary: string
  
  // Borders
  borderDefault: string
  borderSubtle: string
  borderFocus: string
  
  // Text
  textPrimary: string
  textSecondary: string
  textTertiary: string
  textAccent: string
  
  // Semantic colors
  accentPrimary: string
  accentSuccess: string
  accentWarning: string
  accentError: string
  accentInfo: string
  
  // Status indicators
  statusEnabled: string
  statusDisabled: string
  statusPending: string
}

export interface Theme {
  name: string
  displayName: string
  colors: ThemeColors
}

export const themes: Record<string, Theme> = {
  'slate-dark': {
    name: 'slate-dark',
    displayName: 'Slate Dark (Default)',
    colors: {
      bgPrimary: '15 23 42',        // slate-950
      bgSecondary: '30 41 59',      // slate-900
      bgTertiary: '51 65 85',       // slate-800
      borderDefault: '51 65 85',    // slate-800
      borderSubtle: '71 85 105',    // slate-700
      borderFocus: '37 99 235',     // blue-600
      textPrimary: '241 245 249',   // slate-100
      textSecondary: '203 213 225', // slate-300
      textTertiary: '203 213 225',  // slate-300
      textAccent: '96 165 250',     // blue-400
      accentPrimary: '96 165 250',  // blue-400
      accentSuccess: '34 197 94',   // green-500
      accentWarning: '251 146 60',  // orange-400
      accentError: '239 68 68',     // red-500
      accentInfo: '59 130 246',     // blue-500
      statusEnabled: '34 197 94',   // green-500
      statusDisabled: '203 213 225', // slate-300
      statusPending: '251 146 60',  // orange-400
    },
  },
  'dracula': {
    name: 'dracula',
    displayName: 'Dracula',
    colors: {
      bgPrimary: '40 42 54',
      bgSecondary: '68 71 90',
      bgTertiary: '98 114 164',
      borderDefault: '98 114 164',
      borderSubtle: '68 71 90',
      borderFocus: '189 147 249',
      textPrimary: '248 248 242',
      textSecondary: '241 250 140',
      textTertiary: '248 248 242',
      textAccent: '189 147 249',
      accentPrimary: '189 147 249',  // purple
      accentSuccess: '80 250 123',   // green
      accentWarning: '255 184 108',  // orange
      accentError: '255 85 85',      // red
      accentInfo: '139 233 253',     // cyan
      statusEnabled: '80 250 123',
      statusDisabled: '248 248 242',
      statusPending: '255 184 108',
    },
  },
  'tokyo-night': {
    name: 'tokyo-night',
    displayName: 'Tokyo Night',
    colors: {
      bgPrimary: '26 27 38',
      bgSecondary: '36 40 59',
      bgTertiary: '65 72 104',
      borderDefault: '65 72 104',
      borderSubtle: '36 40 59',
      borderFocus: '122 162 247',
      textPrimary: '192 202 245',
      textSecondary: '169 177 214',
      textTertiary: '192 202 245',
      textAccent: '122 162 247',
      accentPrimary: '122 162 247',  // blue
      accentSuccess: '158 206 106',  // green
      accentWarning: '224 175 104',  // yellow
      accentError: '247 118 142',    // red
      accentInfo: '125 207 255',     // cyan
      statusEnabled: '158 206 106',
      statusDisabled: '192 202 245',
      statusPending: '224 175 104',
    },
  },
  'catppuccin-mocha': {
    name: 'catppuccin-mocha',
    displayName: 'Catppuccin Mocha',
    colors: {
      bgPrimary: '30 30 46',
      bgSecondary: '49 50 68',
      bgTertiary: '69 71 90',
      borderDefault: '69 71 90',
      borderSubtle: '49 50 68',
      borderFocus: '137 180 250',
      textPrimary: '205 214 244',
      textSecondary: '186 194 222',
      textTertiary: '186 194 222',
      textAccent: '137 180 250',
      accentPrimary: '137 180 250',  // blue
      accentSuccess: '166 227 161',  // green
      accentWarning: '249 226 175',  // yellow
      accentError: '243 139 168',    // red
      accentInfo: '137 220 235',     // sky
      statusEnabled: '166 227 161',
      statusDisabled: '186 194 222',
      statusPending: '249 226 175',
    },
  },
  'material-light': {
    name: 'material-light',
    displayName: 'Material Light',
    colors: {
      bgPrimary: '250 250 250',
      bgSecondary: '255 255 255',
      bgTertiary: '245 245 245',
      borderDefault: '224 224 224',
      borderSubtle: '238 238 238',
      borderFocus: '25 118 210',
      textPrimary: '33 33 33',
      textSecondary: '97 97 97',
      textTertiary: '97 97 97',
      textAccent: '25 118 210',
      accentPrimary: '25 118 210',   // blue-700
      accentSuccess: '46 125 50',    // green-600
      accentWarning: '230 81 0',    // orange-600
      accentError: '211 47 47',      // red-600
      accentInfo: '2 119 189',       // light-blue-600
      statusEnabled: '46 125 50',
      statusDisabled: '97 97 97',
      statusPending: '230 81 0',
    },
  },
  'catppuccin-latte': {
    name: 'catppuccin-latte',
    displayName: 'Catppuccin Latte',
    colors: {
      bgPrimary: '239 241 245',
      bgSecondary: '230 233 239',
      bgTertiary: '220 224 232',
      borderDefault: '172 176 190',
      borderSubtle: '204 208 218',
      borderFocus: '30 102 245',
      textPrimary: '76 79 105',
      textSecondary: '92 95 119',
      textTertiary: '92 95 119',
      textAccent: '30 102 245',
      accentPrimary: '30 102 245',   // blue
      accentSuccess: '50 128 34',    // green
      accentWarning: '196 124 26',   // yellow
      accentError: '210 15 57',      // red
      accentInfo: '4 124 142',       // sky
      statusEnabled: '50 128 34',
      statusDisabled: '92 95 119',
      statusPending: '196 124 26',
    },
  },
  'mathias': {
    name: 'mathias',
    displayName: 'Mathias',
    colors: {
      bgPrimary: '0 0 0',            // pure black background
      bgSecondary: '30 30 30',       // dark grey surface
      bgTertiary: '55 55 55',        // lighter grey
      borderDefault: '55 55 55',     // color8 (bright black)
      borderSubtle: '85 85 85',
      borderFocus: '196 141 255',    // color4 (blue/purple)
      textPrimary: '242 242 242',    // color7 (white)
      textSecondary: '187 187 187',  // foreground
      textTertiary: '187 187 187',   // muted grey
      textAccent: '196 141 255',     // color4 (blue/purple)
      accentPrimary: '196 141 255',  // color4 (blue/purple)
      accentSuccess: '166 227 45',   // color2 (green)
      accentWarning: '252 149 30',   // color3 (yellow/orange)
      accentError: '229 34 34',      // color1 (red)
      accentInfo: '103 217 240',     // color6 (cyan)
      statusEnabled: '166 227 45',   // color2 (green)
      statusDisabled: '187 187 187',    // color8 (bright black)
      statusPending: '252 149 30',   // color3 (yellow/orange)
    },
  },
  'tokyo-night-day': {
    name: 'tokyo-night-day',
    displayName: 'Tokyo Night Day',
    colors: {
      bgPrimary: '225 226 231',      // #e1e2e7 canvas
      bgSecondary: '237 238 242',    // light surface
      bgTertiary: '200 201 210',     // #b4b5b9 black (normal)
      borderDefault: '161 166 197',  // #a1a6c5 bright black
      borderSubtle: '200 201 205',
      borderFocus: '46 125 233',     // #2e7de9 blue
      textPrimary: '55 96 191',      // #3760bf foreground
      textSecondary: '97 114 176',   // #6172b0 white (normal)
      textTertiary: '55 96 191',   // #848cb5 comment
      textAccent: '46 125 233',      // #2e7de9 blue
      accentPrimary: '46 125 233',   // #2e7de9 blue
      accentSuccess: '88 117 57',    // #587539 green
      accentWarning: '177 92 0',     // #b15c00 orange
      accentError: '245 42 101',     // #f52a65 red
      accentInfo: '0 113 151',       // #007197 cyan
      statusEnabled: '88 117 57',    // #587539 green
      statusDisabled: '55 96 191', // #848cb5 comment
      statusPending: '177 92 0',     // #b15c00 orange
    },
  },
  'tokyo-night-storm': {
    name: 'tokyo-night-storm',
    displayName: 'Tokyo Night Storm',
    colors: {
      bgPrimary: '36 40 59',         // #24283b background
      bgSecondary: '29 32 47',       // #1d202f black (normal)
      bgTertiary: '65 72 104',       // #414868 bright black
      borderDefault: '65 72 104',    // #414868 bright black
      borderSubtle: '90 100 140',
      borderFocus: '122 162 247',    // #7aa2f7 blue
      textPrimary: '192 202 245',    // #c0caf5 foreground
      textSecondary: '169 177 214',  // #a9b1d6 white (normal)
      textTertiary: '192 202 245',     // #565f89 comment
      textAccent: '122 162 247',     // #7aa2f7 blue
      accentPrimary: '122 162 247',  // #7aa2f7 blue
      accentSuccess: '158 206 106',  // #9ece6a green
      accentWarning: '224 175 104',  // #e0af68 yellow
      accentError: '247 118 142',    // #f7768e red
      accentInfo: '125 207 255',     // #7dcfff cyan
      statusEnabled: '158 206 106',  // #9ece6a green
      statusDisabled: '192 202 245',   // #565f89 comment
      statusPending: '224 175 104',  // #e0af68 yellow
    },
  },
  'nord': {
    name: 'nord',
    displayName: 'Nord',
    colors: {
      bgPrimary: '46 52 64',         // #2e3440 polar night
      bgSecondary: '59 66 82',       // #3b4252
      bgTertiary: '76 86 106',       // #4c566a
      borderDefault: '76 86 106',    // #4c566a
      borderSubtle: '94 108 137',
      borderFocus: '136 192 208',    // #88c0d0 frost
      textPrimary: '236 239 244',    // #eceff4 snow storm
      textSecondary: '216 222 233',  // #d8dee9
      textTertiary: '216 222 233',   // #818998
      textAccent: '136 192 208',     // #88c0d0 frost
      accentPrimary: '136 192 208',  // #88c0d0 frost
      accentSuccess: '163 190 140',  // #a3be8c green
      accentWarning: '235 203 139',  // #ebcb8b yellow
      accentError: '191 97 106',     // #bf616a red
      accentInfo: '129 161 193',     // #81a1c1 frost blue
      statusEnabled: '163 190 140',  // #a3be8c
      statusDisabled: '216 222 233',  // #5e6776
      statusPending: '235 203 139',  // #ebcb8b
    },
  },
  'gruvbox-dark': {
    name: 'gruvbox-dark',
    displayName: 'Gruvbox Dark',
    colors: {
      bgPrimary: '40 40 40',         // #282828 bg0
      bgSecondary: '60 56 54',       // #3c3836 bg1
      bgTertiary: '80 73 69',        // #504945 bg2
      borderDefault: '80 73 69',     // #504945
      borderSubtle: '102 92 84',     // #665c54 bg3
      borderFocus: '250 189 47',     // #fabd2f yellow
      textPrimary: '235 219 178',    // #ebdbb2 fg0
      textSecondary: '213 196 161',  // #d5c4a1 fg1
      textTertiary: '213 196 161',   // #bdae93 fg2
      textAccent: '250 189 47',      // #fabd2f yellow
      accentPrimary: '250 189 47',   // #fabd2f yellow
      accentSuccess: '184 187 38',   // #b8bb26 green
      accentWarning: '250 189 47',   // #fabd2f yellow
      accentError: '251 73 52',      // #fb4934 red
      accentInfo: '142 192 124',     // #8ec07c aqua
      statusEnabled: '184 187 38',   // #b8bb26
      statusDisabled: '213 196 161',   // #665c54
      statusPending: '254 128 25',   // #fe8019 orange
    },
  },
  'one-dark': {
    name: 'one-dark',
    displayName: 'One Dark',
    colors: {
      bgPrimary: '40 44 52',         // #282c34
      bgSecondary: '33 37 43',       // #21252b
      bgTertiary: '59 64 72',        // #3b4048
      borderDefault: '59 64 72',     // #3b4048
      borderSubtle: '79 85 95',
      borderFocus: '97 175 239',     // #61afef blue
      textPrimary: '171 178 191',    // #abb2bf
      textSecondary: '132 137 145',  // #848991
      textTertiary: '171 178 191',     // #5c6370
      textAccent: '97 175 239',      // #61afef blue
      accentPrimary: '97 175 239',   // #61afef blue
      accentSuccess: '152 195 121',  // #98c379 green
      accentWarning: '229 192 123',  // #e5c07b yellow
      accentError: '224 108 117',    // #e06c75 red
      accentInfo: '86 182 194',      // #56b6c2 cyan
      statusEnabled: '152 195 121',  // #98c379
      statusDisabled: '171 178 191',   // #5c6370
      statusPending: '209 154 102',  // #d19a66 orange
    },
  },
  'monokai-pro': {
    name: 'monokai-pro',
    displayName: 'Monokai Pro',
    colors: {
      bgPrimary: '45 42 46',         // #2d2a2e
      bgSecondary: '54 50 54',       // #363236
      bgTertiary: '64 56 65',        // #403841
      borderDefault: '64 56 65',     // #403841
      borderSubtle: '84 76 85',
      borderFocus: '255 216 102',    // #ffd866 yellow
      textPrimary: '252 252 250',    // #fcfcfa
      textSecondary: '193 192 192',  // #c1c0c0
      textTertiary: '193 192 192',   // #939293
      textAccent: '255 216 102',     // #ffd866 yellow
      accentPrimary: '255 216 102',  // #ffd866 yellow
      accentSuccess: '169 220 118',  // #a9dc76 green
      accentWarning: '255 216 102',  // #ffd866 yellow
      accentError: '255 97 136',     // #ff6188 red/pink
      accentInfo: '120 220 232',     // #78dce8 cyan
      statusEnabled: '169 220 118',  // #a9dc76
      statusDisabled: '193 192 192', // #939293
      statusPending: '252 152 103',  // #fc9867 orange
    },
  },
  'solarized-dark': {
    name: 'solarized-dark',
    displayName: 'Solarized Dark',
    colors: {
      bgPrimary: '0 43 54',          // #002b36 base03
      bgSecondary: '7 54 66',        // #073642 base02
      bgTertiary: '13 59 72',      // #586e75 base01
      borderDefault: '88 110 117',   // #586e75 base01
      borderSubtle: '101 123 131',   // #657b83 base00
      borderFocus: '38 139 210',     // #268bd2 blue
      textPrimary: '147 161 161',    // #93a1a1 base1
      textSecondary: '131 148 150',  // #839496 base0
      textTertiary: '147 161 161',   // #657b83 base00
      textAccent: '38 139 210',      // #268bd2 blue
      accentPrimary: '38 139 210',   // #268bd2 blue
      accentSuccess: '133 153 0',    // #859900 green
      accentWarning: '181 137 0',    // #b58900 yellow
      accentError: '220 50 47',      // #dc322f red
      accentInfo: '42 161 152',      // #2aa198 cyan
      statusEnabled: '133 153 0',    // #859900
      statusDisabled: '147 161 161', // #657b83
      statusPending: '203 75 22',    // #cb4b16 orange
    },
  },
  'solarized-light': {
    name: 'solarized-light',
    displayName: 'Solarized Light',
    colors: {
      bgPrimary: '253 246 227',      // #fdf6e3 base3
      bgSecondary: '238 232 213',    // #eee8d5 base2
      bgTertiary: '220 212 190',     // #93a1a1 base1
      borderDefault: '147 161 161',  // #93a1a1 base1
      borderSubtle: '131 148 150',   // #839496 base0
      borderFocus: '38 139 210',     // #268bd2 blue
      textPrimary: '7 54 66',        // #073642 base02
      textSecondary: '88 110 117',   // #586e75 base01
      textTertiary: '7 54 66',   // #657b83 base00
      textAccent: '38 139 210',      // #268bd2 blue
      accentPrimary: '38 139 210',   // #268bd2 blue
      accentSuccess: '101 116 0',    // #859900 green
      accentWarning: '136 103 0',    // #b58900 yellow
      accentError: '220 50 47',      // #dc322f red
      accentInfo: '32 122 115',      // #2aa198 cyan
      statusEnabled: '101 116 0',    // #859900
      statusDisabled: '7 54 66', // #657b83
      statusPending: '152 56 16',    // #cb4b16 orange
    },
  },
  'gruvbox-light': {
    name: 'gruvbox-light',
    displayName: 'Gruvbox Light',
    colors: {
      bgPrimary: '251 241 199',      // #fbf1c7 bg0
      bgSecondary: '235 219 178',    // #ebdbb2 bg1
      bgTertiary: '213 196 161',     // #d5c4a1 bg2
      borderDefault: '213 196 161',  // #d5c4a1
      borderSubtle: '189 174 147',   // #bdae93 bg3
      borderFocus: '181 118 20',     // #b57614 dark yellow
      textPrimary: '60 56 54',       // #3c3836 fg0
      textSecondary: '80 73 69',     // #504945 fg1
      textTertiary: '80 73 69',     // #665c54 fg2
      textAccent: '143 86 17',      // #b57614
      accentPrimary: '143 86 17',   // #b57614
      accentSuccess: '93 90 8',   // #79740e green
      accentWarning: '143 86 17',   // #b57614 yellow
      accentError: '204 36 29',      // #cc241d red
      accentInfo: '66 100 70',       // #427b58 aqua
      statusEnabled: '93 90 8',   // #79740e
      statusDisabled: '80 73 69',   // #665c54
      statusPending: '175 58 3',     // #af3a03 orange
    },
  },
  'github-dark': {
    name: 'github-dark',
    displayName: 'GitHub Dark',
    colors: {
      bgPrimary: '13 17 23',         // #0d1117
      bgSecondary: '22 27 34',       // #161b22
      bgTertiary: '33 38 45',        // #21262d
      borderDefault: '33 38 45',     // #21262d
      borderSubtle: '48 54 61',      // #30363d
      borderFocus: '88 166 255',     // #58a6ff blue
      textPrimary: '201 209 217',    // #c9d1d9
      textSecondary: '139 148 158',  // #8b949e
      textTertiary: '139 148 158',   // #6e7681
      textAccent: '88 166 255',      // #58a6ff blue
      accentPrimary: '88 166 255',   // #58a6ff blue
      accentSuccess: '63 185 80',    // #3fb950 green
      accentWarning: '210 153 34',   // #d29922 yellow
      accentError: '248 81 73',      // #f85149 red
      accentInfo: '57 197 207',      // #39c5cf cyan
      statusEnabled: '63 185 80',    // #3fb950
      statusDisabled: '139 148 158', // #6e7681
      statusPending: '219 109 40',   // #db6d28 orange
    },
  },
  'rose-pine': {
    name: 'rose-pine',
    displayName: 'Rosé Pine',
    colors: {
      bgPrimary: '25 23 36',         // #191724 base
      bgSecondary: '31 29 46',       // #1f1d2e surface
      bgTertiary: '38 35 58',        // #26233a overlay
      borderDefault: '38 35 58',     // #26233a
      borderSubtle: '55 50 79',
      borderFocus: '235 188 186',    // #ebbcba rose
      textPrimary: '224 222 244',    // #e0def4 text
      textSecondary: '144 140 170',  // #908caa muted
      textTertiary: '144 140 170',   // #6e6a86 inactive
      textAccent: '235 188 186',     // #ebbcba rose
      accentPrimary: '235 188 186',  // #ebbcba rose
      accentSuccess: '49 116 143',   // #31748f pine
      accentWarning: '246 193 119',  // #f6c177 gold
      accentError: '235 111 146',    // #eb6f92 love
      accentInfo: '156 207 216',     // #9ccfd8 foam
      statusEnabled: '49 116 143',   // #31748f pine
      statusDisabled: '144 140 170', // #6e6a86 inactive
      statusPending: '246 193 119',  // #f6c177 gold
    },
  },
  'everforest': {
    name: 'everforest',
    displayName: 'Everforest',
    colors: {
      bgPrimary: '45 53 59',         // #2d353b bg0
      bgSecondary: '52 63 68',       // #343f44 bg1
      bgTertiary: '61 72 77',        // #3d484d bg2
      borderDefault: '61 72 77',     // #3d484d
      borderSubtle: '78 90 94',      // #4e5a5e bg3
      borderFocus: '167 192 128',    // #a7c080 green
      textPrimary: '211 198 170',    // #d3c6aa fg
      textSecondary: '157 169 160',  // #9da9a0
      textTertiary: '211 198 170',   // #7a8478
      textAccent: '167 192 128',     // #a7c080 green
      accentPrimary: '167 192 128',  // #a7c080 green
      accentSuccess: '167 192 128',  // #a7c080 green
      accentWarning: '219 188 127',  // #dbbc7f yellow
      accentError: '230 126 128',    // #e67e80 red
      accentInfo: '127 187 179',     // #7fbbb3 blue
      statusEnabled: '167 192 128',  // #a7c080
      statusDisabled: '211 198 170', // #7a8478
      statusPending: '230 152 117',  // #e69875 orange
    },
  },
  'c64': {
    name: 'c64',
    displayName: 'C64',
    colors: {
      bgPrimary: '64 49 141',        // #40318d blue (screen background)
      bgSecondary: '9 3 0',          // #090300 black
      bgTertiary: '139 63 150',      // #8b3f96 magenta
      borderDefault: '139 63 150',   // #8b3f96 magenta
      borderSubtle: '120 105 196',   // #7869c4 light purple
      borderFocus: '255 255 255',    // #ffffff white
      textPrimary: '247 247 247',    // #f7f7f7 bright white
      textSecondary: '120 105 196',  // #7869c4 light purple (foreground)
      textTertiary: '247 247 247',   // #67b6bd cyan
      textAccent: '255 255 255',     // #ffffff white
      accentPrimary: '255 255 255',  // #ffffff white
      accentSuccess: '85 160 73',    // #55a049 green
      accentWarning: '191 206 114',  // #bfce72 yellow
      accentError: '136 57 50',      // #883932 red
      accentInfo: '103 182 189',     // #67b6bd cyan
      statusEnabled: '85 160 73',    // #55a049
      statusDisabled: '247 247 247', // #7869c4
      statusPending: '191 206 114',  // #bfce72
    },
  },
  'github-light': {
    name: 'github-light',
    displayName: 'GitHub Light',
    colors: {
      bgPrimary: '255 255 255',      // #ffffff default bg
      bgSecondary: '246 248 250',    // #f6f8fa muted bg
      bgTertiary: '233 236 239',     // #e9ecef subtle bg
      borderDefault: '208 215 222',  // #d0d7de default border
      borderSubtle: '225 228 232',   // #e1e4e8 subtle border
      borderFocus: '9 105 218',      // #0969da accent blue
      textPrimary: '31 35 40',       // #1f2328 default fg
      textSecondary: '89 99 110',    // #59636e muted fg
      textTertiary: '89 99 110',   // #6e7681 tertiary fg
      textAccent: '9 105 218',       // #0969da accent blue
      accentPrimary: '9 105 218',    // #0969da accent blue
      accentSuccess: '26 127 55',    // #1a7f37 success green
      accentWarning: '154 103 0',    // #9a6700 attention
      accentError: '209 36 47',      // #d1242f danger red
      accentInfo: '9 105 218',       // #0969da blue
      statusEnabled: '26 127 55',    // #1a7f37
      statusDisabled: '89 99 110', // #6e7681
      statusPending: '154 103 0',    // #9a6700
    },
  },
  'jazz': {
    name: 'jazz',
    displayName: 'Jazz',
    colors: {
      bgPrimary: '243 242 241',      // #f3f2f1 background
      bgSecondary: '255 255 255',    // #ffffff elevated surface
      bgTertiary: '226 226 224',     // #e2e2e0 subtle surface
      borderDefault: '135 139 145',  // #878b91 grey
      borderSubtle: '200 200 198',   // #c8c8c6
      borderFocus: '140 113 191',    // #8c71bf blue/purple
      textPrimary: '63 63 63',       // #3f3f3f foreground
      textSecondary: '51 55 76',     // #33374c bold
      textTertiary: '51 55 76',     // #5e6091 bright cyan
      textAccent: '140 113 191',     // #8c71bf blue
      accentPrimary: '140 113 191',  // #8c71bf blue/purple
      accentSuccess: '74 107 42',   // #668e3d green
      accentWarning: '160 112 32',   // #c49041 yellow
      accentError: '176 64 80',    // #e06c75 red
      accentInfo: '94 96 145',       // #5e6091 bright cyan
      statusEnabled: '74 107 42',   // #668e3d
      statusDisabled: '51 55 76', // #878b91
      statusPending: '160 112 32',   // #c49041
    },
  },
  'ic-green-ppl': {
    name: 'ic-green-ppl',
    displayName: 'Matrix',
    colors: {
      bgPrimary: '44 44 44',         // #2c2c2c background
      bgSecondary: '1 68 1',         // #014401 black (green-tinted)
      bgTertiary: '3 92 3',          // #035c03 bright black (green-tinted)
      borderDefault: '3 92 3',       // #035c03
      borderSubtle: '65 166 56',     // #41a638 green
      borderFocus: '71 250 107',     // #47fa6b cursor green
      textPrimary: '224 241 220',    // #e0f1dc foreground
      textSecondary: '172 251 128',  // #acfb80 bold
      textTertiary: '172 251 128',     // #41a638 green
      textAccent: '71 250 107',      // #47fa6b cursor green
      accentPrimary: '71 250 107',   // #47fa6b bright green
      accentSuccess: '65 166 56',    // #41a638 green
      accentWarning: '118 168 49',   // #76a831 yellow
      accentError: '255 39 54',      // #ff2736 red
      accentInfo: '46 195 185',      // #2ec3b9 blue
      statusEnabled: '65 166 56',    // #41a638
      statusDisabled: '172 251 128',  // #3ca078 cyan (muted)
      statusPending: '118 168 49',   // #76a831
    },
  },
  'material-sky-blue': {
    name: 'material-sky-blue',
    displayName: 'Material Sky Blue',
    colors: {
      bgPrimary: '38 50 56',         // #263238 background
      bgSecondary: '46 60 67',       // #2e3c43 lighter bg
      bgTertiary: '53 71 77',        // #35474d selection bg
      borderDefault: '53 71 77',     // #35474d
      borderSubtle: '70 88 94',      // #46585e
      borderFocus: '79 195 247',     // #4fc3f7 sky blue
      textPrimary: '238 255 255',    // #eeffff foreground
      textSecondary: '178 204 214',  // #b2ccd6
      textTertiary: '178 204 214',    // #546e7a comments
      textAccent: '79 195 247',      // #4fc3f7 sky blue
      accentPrimary: '79 195 247',   // #4fc3f7 sky blue
      accentSuccess: '195 232 141',  // #c3e88d green
      accentWarning: '255 203 107',  // #ffcb6b yellow
      accentError: '240 113 120',    // #f07178 red
      accentInfo: '137 221 255',     // #89ddff cyan
      statusEnabled: '195 232 141',  // #c3e88d
      statusDisabled: '178 204 214',  // #546e7a
      statusPending: '255 203 107',  // #ffcb6b
    },
  },
  'material-palenight': {
    name: 'material-palenight',
    displayName: 'Material Palenight',
    colors: {
      bgPrimary: '41 45 62',         // #292d3e background
      bgSecondary: '50 55 75',       // #32374b lighter bg
      bgTertiary: '65 72 99',        // #414863 selection bg
      borderDefault: '65 72 99',     // #414863
      borderSubtle: '82 87 131',     // #525783
      borderFocus: '130 170 255',    // #82aaff blue
      textPrimary: '238 255 255',    // #eeffff foreground
      textSecondary: '191 199 213',  // #bfc7d5
      textTertiary: '191 199 213',   // #676e95 comments
      textAccent: '130 170 255',     // #82aaff blue
      accentPrimary: '130 170 255',  // #82aaff blue
      accentSuccess: '195 232 141',  // #c3e88d green
      accentWarning: '255 203 107',  // #ffcb6b yellow
      accentError: '240 113 120',    // #f07178 red
      accentInfo: '137 221 255',     // #89ddff cyan
      statusEnabled: '195 232 141',  // #c3e88d
      statusDisabled: '191 199 213', // #676e95
      statusPending: '255 203 107',  // #ffcb6b
    },
  },
  'material-deep-ocean': {
    name: 'material-deep-ocean',
    displayName: 'Material Deep Ocean',
    colors: {
      bgPrimary: '15 17 26',         // #0f111a background
      bgSecondary: '24 26 38',       // #181a26 lighter bg
      bgTertiary: '31 34 51',        // #1f2233 selection bg
      borderDefault: '31 34 51',     // #1f2233
      borderSubtle: '43 46 64',      // #2b2e40
      borderFocus: '132 255 255',    // #84ffff cyan
      textPrimary: '166 172 205',    // #a6accd foreground
      textSecondary: '113 124 180',  // #717cb4
      textTertiary: '113 124 180',     // #525b8c comments
      textAccent: '132 255 255',     // #84ffff cyan
      accentPrimary: '132 255 255',  // #84ffff cyan
      accentSuccess: '195 232 141',  // #c3e88d green
      accentWarning: '255 203 107',  // #ffcb6b yellow
      accentError: '240 113 120',    // #f07178 red
      accentInfo: '132 255 255',     // #84ffff cyan
      statusEnabled: '195 232 141',  // #c3e88d
      statusDisabled: '113 124 180',   // #525b8c
      statusPending: '255 203 107',  // #ffcb6b
    },
  },
  'catppuccin-frappe': {
    name: 'catppuccin-frappe',
    displayName: 'Catppuccin Frappé',
    colors: {
      bgPrimary: '48 52 70',         // #303446 base
      bgSecondary: '41 44 60',       // #292c3c mantle
      bgTertiary: '65 69 89',        // #414559 surface0
      borderDefault: '65 69 89',     // #414559
      borderSubtle: '81 87 109',     // #51576d surface1
      borderFocus: '140 170 238',    // #8caaee blue
      textPrimary: '198 208 245',    // #c6d0f5 text
      textSecondary: '181 191 226',  // #b5bfe2 subtext0
      textTertiary: '181 191 226',   // #a5adce subtext1
      textAccent: '140 170 238',     // #8caaee blue
      accentPrimary: '140 170 238',  // #8caaee blue
      accentSuccess: '166 209 137',  // #a6d189 green
      accentWarning: '229 200 144',  // #e5c890 yellow
      accentError: '231 130 132',    // #e78284 red
      accentInfo: '153 209 219',     // #99d1db sky
      statusEnabled: '166 209 137',  // #a6d189
      statusDisabled: '181 191 226', // #949cbb overlay0
      statusPending: '229 200 144',  // #e5c890
    },
  },
  'catppuccin-macchiato': {
    name: 'catppuccin-macchiato',
    displayName: 'Catppuccin Macchiato',
    colors: {
      bgPrimary: '36 39 58',         // #24273a base
      bgSecondary: '30 32 48',       // #1e2030 mantle
      bgTertiary: '54 58 79',        // #363a4f surface0
      borderDefault: '54 58 79',     // #363a4f
      borderSubtle: '73 77 100',     // #494d64 surface1
      borderFocus: '138 173 244',    // #8aadf4 blue
      textPrimary: '202 211 245',    // #cad3f5 text
      textSecondary: '184 192 224',  // #b8c0e0 subtext0
      textTertiary: '184 192 224',   // #a5adcb subtext1
      textAccent: '138 173 244',     // #8aadf4 blue
      accentPrimary: '138 173 244',  // #8aadf4 blue
      accentSuccess: '166 218 149',  // #a6da95 green
      accentWarning: '238 212 159',  // #eed49f yellow
      accentError: '237 135 150',    // #ed8796 red
      accentInfo: '145 215 227',     // #91d7e3 sky
      statusEnabled: '166 218 149',  // #a6da95
      statusDisabled: '184 192 224', // #838ba7 overlay0
      statusPending: '238 212 159',  // #eed49f
    },
  },
}

export const defaultTheme = 'slate-dark'

// ---------------------------------------------------------------------------
// Color metadata — used by the custom theme editor to render grouped pickers
// ---------------------------------------------------------------------------

export interface ColorMeta {
  key: keyof ThemeColors
  label: string
  group: 'Backgrounds' | 'Borders' | 'Text' | 'Semantic' | 'Status'
}

export const colorMetadata: ColorMeta[] = [
  { key: 'bgPrimary',        label: 'Primary Background',    group: 'Backgrounds' },
  { key: 'bgSecondary',      label: 'Secondary Background',  group: 'Backgrounds' },
  { key: 'bgTertiary',       label: 'Tertiary Background',   group: 'Backgrounds' },
  { key: 'borderDefault',    label: 'Default Border',        group: 'Borders' },
  { key: 'borderSubtle',     label: 'Subtle Border',         group: 'Borders' },
  { key: 'borderFocus',      label: 'Focus Border',          group: 'Borders' },
  { key: 'textPrimary',      label: 'Primary Text',          group: 'Text' },
  { key: 'textSecondary',    label: 'Secondary Text',        group: 'Text' },
  { key: 'textTertiary',     label: 'Tertiary Text',         group: 'Text' },
  { key: 'textAccent',       label: 'Accent Text',           group: 'Text' },
  { key: 'accentPrimary',    label: 'Primary Accent',        group: 'Semantic' },
  { key: 'accentSuccess',    label: 'Success',               group: 'Semantic' },
  { key: 'accentWarning',    label: 'Warning',               group: 'Semantic' },
  { key: 'accentError',      label: 'Error',                 group: 'Semantic' },
  { key: 'accentInfo',       label: 'Info',                  group: 'Semantic' },
  { key: 'statusEnabled',    label: 'Enabled Status',        group: 'Status' },
  { key: 'statusDisabled',   label: 'Disabled Status',       group: 'Status' },
  { key: 'statusPending',    label: 'Pending Status',        group: 'Status' },
]

export const colorGroups = ['Backgrounds', 'Borders', 'Text', 'Semantic', 'Status'] as const

// ---------------------------------------------------------------------------
// Color conversion helpers — theme colors are stored as "R G B" space-separated
// triplets (for Tailwind alpha compatibility).  The editor works in hex.
// ---------------------------------------------------------------------------

/** Convert a hex string (#rrggbb or #rgb) to the "R G B" triplet format. */
export function hexToTriplet(hex: string): string {
  let h = hex.replace('#', '').trim()
  if (h.length === 3) {
    h = h[0] + h[0] + h[1] + h[1] + h[2] + h[2]
  }
  if (h.length !== 6 || !/^[0-9a-fA-F]{6}$/.test(h)) {
    return '0 0 0'
  }
  const r = parseInt(h.slice(0, 2), 16)
  const g = parseInt(h.slice(2, 4), 16)
  const b = parseInt(h.slice(4, 6), 16)
  return `${r} ${g} ${b}`
}

/** Convert a "R G B" triplet back to a #rrggbb hex string. */
export function tripletToHex(triplet: string): string {
  const parts = triplet.trim().split(/\s+/)
  if (parts.length !== 3) return '#000000'
  const [r, g, b] = parts.map(Number)
  if ([r, g, b].some(n => isNaN(n) || n < 0 || n > 255)) return '#000000'
  const toHex = (n: number) => Math.round(n).toString(16).padStart(2, '0')
  return `#${toHex(r)}${toHex(g)}${toHex(b)}`
}

/** Convert a ThemeColors object to a hex record (for the editor form). */
export function colorsToHex(colors: ThemeColors): Record<keyof ThemeColors, string> {
  const result = {} as Record<keyof ThemeColors, string>
  for (const meta of colorMetadata) {
    result[meta.key] = tripletToHex(colors[meta.key])
  }
  return result
}

/** Convert a hex record back to a ThemeColors object. */
export function hexToColors(hex: Record<keyof ThemeColors, string>): ThemeColors {
  const result = {} as ThemeColors
  for (const meta of colorMetadata) {
    result[meta.key] = hexToTriplet(hex[meta.key])
  }
  return result
}

/** Generate a unique theme name from a display name. */
export function slugifyThemeName(displayName: string): string {
  return 'custom-' + displayName
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
}

/** Deep-clone a Theme object. */
export function cloneTheme(theme: Theme): Theme {
  return {
    name: theme.name,
    displayName: theme.displayName,
    colors: { ...theme.colors },
  }
}

/** Create a blank ThemeColors with all colors set to a sensible dark default. */
export function blankColors(): ThemeColors {
  return {
    bgPrimary: '15 23 42',
    bgSecondary: '30 41 59',
    bgTertiary: '51 65 85',
    borderDefault: '51 65 85',
    borderSubtle: '71 85 105',
    borderFocus: '37 99 235',
    textPrimary: '241 245 249',
    textSecondary: '203 213 225',
    textTertiary: '148 163 184',
    textAccent: '37 99 235',
    accentPrimary: '37 99 235',
    accentSuccess: '34 197 94',
    accentWarning: '251 146 60',
    accentError: '239 68 68',
    accentInfo: '59 130 246',
    statusEnabled: '34 197 94',
    statusDisabled: '100 116 139',
    statusPending: '251 146 60',
  }
}
