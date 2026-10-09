(function () {
	'use strict';

	function _mergeNamespaces(n, m) {
		m.forEach(function (e) {
			e && typeof e !== 'string' && !Array.isArray(e) && Object.keys(e).forEach(function (k) {
				if (k !== 'default' && !(k in n)) {
					var d = Object.getOwnPropertyDescriptor(e, k);
					Object.defineProperty(n, k, d.get ? d : {
						enumerable: true,
						get: function () { return e[k]; }
					});
				}
			});
		});
		return Object.freeze(n);
	}

	function getDefaultExportFromCjs (x) {
		return x && x.__esModule && Object.prototype.hasOwnProperty.call(x, 'default') ? x['default'] : x;
	}

	function getAugmentedNamespace(n) {
	  if (n.__esModule) return n;
	  var f = n.default;
		if (typeof f == "function") {
			var a = function a () {
				if (this instanceof a) {
	        return Reflect.construct(f, arguments, this.constructor);
				}
				return f.apply(this, arguments);
			};
			a.prototype = f.prototype;
	  } else a = {};
	  Object.defineProperty(a, '__esModule', {value: true});
		Object.keys(n).forEach(function (k) {
			var d = Object.getOwnPropertyDescriptor(n, k);
			Object.defineProperty(a, k, d.get ? d : {
				enumerable: true,
				get: function () {
					return n[k];
				}
			});
		});
		return a;
	}

	var jsxRuntime = {exports: {}};

	var reactJsxRuntime_production_min = {};

	var react = {exports: {}};

	var react_production_min = {};

	/**
	 * @license React
	 * react.production.min.js
	 *
	 * Copyright (c) Facebook, Inc. and its affiliates.
	 *
	 * This source code is licensed under the MIT license found in the
	 * LICENSE file in the root directory of this source tree.
	 */

	var hasRequiredReact_production_min;

	function requireReact_production_min () {
		if (hasRequiredReact_production_min) return react_production_min;
		hasRequiredReact_production_min = 1;

		var l = Symbol.for("react.element"),
		  n = Symbol.for("react.portal"),
		  p = Symbol.for("react.fragment"),
		  q = Symbol.for("react.strict_mode"),
		  r = Symbol.for("react.profiler"),
		  t = Symbol.for("react.provider"),
		  u = Symbol.for("react.context"),
		  v = Symbol.for("react.forward_ref"),
		  w = Symbol.for("react.suspense"),
		  x = Symbol.for("react.memo"),
		  y = Symbol.for("react.lazy"),
		  z = Symbol.iterator;
		function A(a) {
		  if (null === a || "object" !== typeof a) return null;
		  a = z && a[z] || a["@@iterator"];
		  return "function" === typeof a ? a : null;
		}
		var B = {
		    isMounted: function () {
		      return !1;
		    },
		    enqueueForceUpdate: function () {},
		    enqueueReplaceState: function () {},
		    enqueueSetState: function () {}
		  },
		  C = Object.assign,
		  D = {};
		function E(a, b, e) {
		  this.props = a;
		  this.context = b;
		  this.refs = D;
		  this.updater = e || B;
		}
		E.prototype.isReactComponent = {};
		E.prototype.setState = function (a, b) {
		  if ("object" !== typeof a && "function" !== typeof a && null != a) throw Error("setState(...): takes an object of state variables to update or a function which returns an object of state variables.");
		  this.updater.enqueueSetState(this, a, b, "setState");
		};
		E.prototype.forceUpdate = function (a) {
		  this.updater.enqueueForceUpdate(this, a, "forceUpdate");
		};
		function F() {}
		F.prototype = E.prototype;
		function G(a, b, e) {
		  this.props = a;
		  this.context = b;
		  this.refs = D;
		  this.updater = e || B;
		}
		var H = G.prototype = new F();
		H.constructor = G;
		C(H, E.prototype);
		H.isPureReactComponent = !0;
		var I = Array.isArray,
		  J = Object.prototype.hasOwnProperty,
		  K = {
		    current: null
		  },
		  L = {
		    key: !0,
		    ref: !0,
		    __self: !0,
		    __source: !0
		  };
		function M(a, b, e) {
		  var d,
		    c = {},
		    k = null,
		    h = null;
		  if (null != b) for (d in void 0 !== b.ref && (h = b.ref), void 0 !== b.key && (k = "" + b.key), b) J.call(b, d) && !L.hasOwnProperty(d) && (c[d] = b[d]);
		  var g = arguments.length - 2;
		  if (1 === g) c.children = e;else if (1 < g) {
		    for (var f = Array(g), m = 0; m < g; m++) f[m] = arguments[m + 2];
		    c.children = f;
		  }
		  if (a && a.defaultProps) for (d in g = a.defaultProps, g) void 0 === c[d] && (c[d] = g[d]);
		  return {
		    $$typeof: l,
		    type: a,
		    key: k,
		    ref: h,
		    props: c,
		    _owner: K.current
		  };
		}
		function N(a, b) {
		  return {
		    $$typeof: l,
		    type: a.type,
		    key: b,
		    ref: a.ref,
		    props: a.props,
		    _owner: a._owner
		  };
		}
		function O(a) {
		  return "object" === typeof a && null !== a && a.$$typeof === l;
		}
		function escape(a) {
		  var b = {
		    "=": "=0",
		    ":": "=2"
		  };
		  return "$" + a.replace(/[=:]/g, function (a) {
		    return b[a];
		  });
		}
		var P = /\/+/g;
		function Q(a, b) {
		  return "object" === typeof a && null !== a && null != a.key ? escape("" + a.key) : b.toString(36);
		}
		function R(a, b, e, d, c) {
		  var k = typeof a;
		  if ("undefined" === k || "boolean" === k) a = null;
		  var h = !1;
		  if (null === a) h = !0;else switch (k) {
		    case "string":
		    case "number":
		      h = !0;
		      break;
		    case "object":
		      switch (a.$$typeof) {
		        case l:
		        case n:
		          h = !0;
		      }
		  }
		  if (h) return h = a, c = c(h), a = "" === d ? "." + Q(h, 0) : d, I(c) ? (e = "", null != a && (e = a.replace(P, "$&/") + "/"), R(c, b, e, "", function (a) {
		    return a;
		  })) : null != c && (O(c) && (c = N(c, e + (!c.key || h && h.key === c.key ? "" : ("" + c.key).replace(P, "$&/") + "/") + a)), b.push(c)), 1;
		  h = 0;
		  d = "" === d ? "." : d + ":";
		  if (I(a)) for (var g = 0; g < a.length; g++) {
		    k = a[g];
		    var f = d + Q(k, g);
		    h += R(k, b, e, f, c);
		  } else if (f = A(a), "function" === typeof f) for (a = f.call(a), g = 0; !(k = a.next()).done;) k = k.value, f = d + Q(k, g++), h += R(k, b, e, f, c);else if ("object" === k) throw b = String(a), Error("Objects are not valid as a React child (found: " + ("[object Object]" === b ? "object with keys {" + Object.keys(a).join(", ") + "}" : b) + "). If you meant to render a collection of children, use an array instead.");
		  return h;
		}
		function S(a, b, e) {
		  if (null == a) return a;
		  var d = [],
		    c = 0;
		  R(a, d, "", "", function (a) {
		    return b.call(e, a, c++);
		  });
		  return d;
		}
		function T(a) {
		  if (-1 === a._status) {
		    var b = a._result;
		    b = b();
		    b.then(function (b) {
		      if (0 === a._status || -1 === a._status) a._status = 1, a._result = b;
		    }, function (b) {
		      if (0 === a._status || -1 === a._status) a._status = 2, a._result = b;
		    });
		    -1 === a._status && (a._status = 0, a._result = b);
		  }
		  if (1 === a._status) return a._result.default;
		  throw a._result;
		}
		var U = {
		    current: null
		  },
		  V = {
		    transition: null
		  },
		  W = {
		    ReactCurrentDispatcher: U,
		    ReactCurrentBatchConfig: V,
		    ReactCurrentOwner: K
		  };
		function X() {
		  throw Error("act(...) is not supported in production builds of React.");
		}
		react_production_min.Children = {
		  map: S,
		  forEach: function (a, b, e) {
		    S(a, function () {
		      b.apply(this, arguments);
		    }, e);
		  },
		  count: function (a) {
		    var b = 0;
		    S(a, function () {
		      b++;
		    });
		    return b;
		  },
		  toArray: function (a) {
		    return S(a, function (a) {
		      return a;
		    }) || [];
		  },
		  only: function (a) {
		    if (!O(a)) throw Error("React.Children.only expected to receive a single React element child.");
		    return a;
		  }
		};
		react_production_min.Component = E;
		react_production_min.Fragment = p;
		react_production_min.Profiler = r;
		react_production_min.PureComponent = G;
		react_production_min.StrictMode = q;
		react_production_min.Suspense = w;
		react_production_min.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED = W;
		react_production_min.act = X;
		react_production_min.cloneElement = function (a, b, e) {
		  if (null === a || void 0 === a) throw Error("React.cloneElement(...): The argument must be a React element, but you passed " + a + ".");
		  var d = C({}, a.props),
		    c = a.key,
		    k = a.ref,
		    h = a._owner;
		  if (null != b) {
		    void 0 !== b.ref && (k = b.ref, h = K.current);
		    void 0 !== b.key && (c = "" + b.key);
		    if (a.type && a.type.defaultProps) var g = a.type.defaultProps;
		    for (f in b) J.call(b, f) && !L.hasOwnProperty(f) && (d[f] = void 0 === b[f] && void 0 !== g ? g[f] : b[f]);
		  }
		  var f = arguments.length - 2;
		  if (1 === f) d.children = e;else if (1 < f) {
		    g = Array(f);
		    for (var m = 0; m < f; m++) g[m] = arguments[m + 2];
		    d.children = g;
		  }
		  return {
		    $$typeof: l,
		    type: a.type,
		    key: c,
		    ref: k,
		    props: d,
		    _owner: h
		  };
		};
		react_production_min.createContext = function (a) {
		  a = {
		    $$typeof: u,
		    _currentValue: a,
		    _currentValue2: a,
		    _threadCount: 0,
		    Provider: null,
		    Consumer: null,
		    _defaultValue: null,
		    _globalName: null
		  };
		  a.Provider = {
		    $$typeof: t,
		    _context: a
		  };
		  return a.Consumer = a;
		};
		react_production_min.createElement = M;
		react_production_min.createFactory = function (a) {
		  var b = M.bind(null, a);
		  b.type = a;
		  return b;
		};
		react_production_min.createRef = function () {
		  return {
		    current: null
		  };
		};
		react_production_min.forwardRef = function (a) {
		  return {
		    $$typeof: v,
		    render: a
		  };
		};
		react_production_min.isValidElement = O;
		react_production_min.lazy = function (a) {
		  return {
		    $$typeof: y,
		    _payload: {
		      _status: -1,
		      _result: a
		    },
		    _init: T
		  };
		};
		react_production_min.memo = function (a, b) {
		  return {
		    $$typeof: x,
		    type: a,
		    compare: void 0 === b ? null : b
		  };
		};
		react_production_min.startTransition = function (a) {
		  var b = V.transition;
		  V.transition = {};
		  try {
		    a();
		  } finally {
		    V.transition = b;
		  }
		};
		react_production_min.unstable_act = X;
		react_production_min.useCallback = function (a, b) {
		  return U.current.useCallback(a, b);
		};
		react_production_min.useContext = function (a) {
		  return U.current.useContext(a);
		};
		react_production_min.useDebugValue = function () {};
		react_production_min.useDeferredValue = function (a) {
		  return U.current.useDeferredValue(a);
		};
		react_production_min.useEffect = function (a, b) {
		  return U.current.useEffect(a, b);
		};
		react_production_min.useId = function () {
		  return U.current.useId();
		};
		react_production_min.useImperativeHandle = function (a, b, e) {
		  return U.current.useImperativeHandle(a, b, e);
		};
		react_production_min.useInsertionEffect = function (a, b) {
		  return U.current.useInsertionEffect(a, b);
		};
		react_production_min.useLayoutEffect = function (a, b) {
		  return U.current.useLayoutEffect(a, b);
		};
		react_production_min.useMemo = function (a, b) {
		  return U.current.useMemo(a, b);
		};
		react_production_min.useReducer = function (a, b, e) {
		  return U.current.useReducer(a, b, e);
		};
		react_production_min.useRef = function (a) {
		  return U.current.useRef(a);
		};
		react_production_min.useState = function (a) {
		  return U.current.useState(a);
		};
		react_production_min.useSyncExternalStore = function (a, b, e) {
		  return U.current.useSyncExternalStore(a, b, e);
		};
		react_production_min.useTransition = function () {
		  return U.current.useTransition();
		};
		react_production_min.version = "18.3.1";
		return react_production_min;
	}

	var hasRequiredReact;

	function requireReact () {
		if (hasRequiredReact) return react.exports;
		hasRequiredReact = 1;

		{
		  react.exports = requireReact_production_min();
		}
		return react.exports;
	}

	/**
	 * @license React
	 * react-jsx-runtime.production.min.js
	 *
	 * Copyright (c) Facebook, Inc. and its affiliates.
	 *
	 * This source code is licensed under the MIT license found in the
	 * LICENSE file in the root directory of this source tree.
	 */

	var hasRequiredReactJsxRuntime_production_min;

	function requireReactJsxRuntime_production_min () {
		if (hasRequiredReactJsxRuntime_production_min) return reactJsxRuntime_production_min;
		hasRequiredReactJsxRuntime_production_min = 1;

		var f = requireReact(),
		  k = Symbol.for("react.element"),
		  l = Symbol.for("react.fragment"),
		  m = Object.prototype.hasOwnProperty,
		  n = f.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED.ReactCurrentOwner,
		  p = {
		    key: !0,
		    ref: !0,
		    __self: !0,
		    __source: !0
		  };
		function q(c, a, g) {
		  var b,
		    d = {},
		    e = null,
		    h = null;
		  void 0 !== g && (e = "" + g);
		  void 0 !== a.key && (e = "" + a.key);
		  void 0 !== a.ref && (h = a.ref);
		  for (b in a) m.call(a, b) && !p.hasOwnProperty(b) && (d[b] = a[b]);
		  if (c && c.defaultProps) for (b in a = c.defaultProps, a) void 0 === d[b] && (d[b] = a[b]);
		  return {
		    $$typeof: k,
		    type: c,
		    key: e,
		    ref: h,
		    props: d,
		    _owner: n.current
		  };
		}
		reactJsxRuntime_production_min.Fragment = l;
		reactJsxRuntime_production_min.jsx = q;
		reactJsxRuntime_production_min.jsxs = q;
		return reactJsxRuntime_production_min;
	}

	var hasRequiredJsxRuntime;

	function requireJsxRuntime () {
		if (hasRequiredJsxRuntime) return jsxRuntime.exports;
		hasRequiredJsxRuntime = 1;

		{
		  jsxRuntime.exports = requireReactJsxRuntime_production_min();
		}
		return jsxRuntime.exports;
	}

	var jsxRuntimeExports = requireJsxRuntime();

	const common = {
	  black: '#000',
	  white: '#fff'
	};
	var common$1 = common;

	const red = {
	  50: '#ffebee',
	  100: '#ffcdd2',
	  200: '#ef9a9a',
	  300: '#e57373',
	  400: '#ef5350',
	  500: '#f44336',
	  600: '#e53935',
	  700: '#d32f2f',
	  800: '#c62828',
	  900: '#b71c1c',
	  A100: '#ff8a80',
	  A200: '#ff5252',
	  A400: '#ff1744',
	  A700: '#d50000'
	};
	var red$1 = red;

	const purple = {
	  50: '#f3e5f5',
	  100: '#e1bee7',
	  200: '#ce93d8',
	  300: '#ba68c8',
	  400: '#ab47bc',
	  500: '#9c27b0',
	  600: '#8e24aa',
	  700: '#7b1fa2',
	  800: '#6a1b9a',
	  900: '#4a148c',
	  A100: '#ea80fc',
	  A200: '#e040fb',
	  A400: '#d500f9',
	  A700: '#aa00ff'
	};
	var purple$1 = purple;

	const blue = {
	  50: '#e3f2fd',
	  100: '#bbdefb',
	  200: '#90caf9',
	  300: '#64b5f6',
	  400: '#42a5f5',
	  500: '#2196f3',
	  600: '#1e88e5',
	  700: '#1976d2',
	  800: '#1565c0',
	  900: '#0d47a1',
	  A100: '#82b1ff',
	  A200: '#448aff',
	  A400: '#2979ff',
	  A700: '#2962ff'
	};
	var blue$1 = blue;

	const lightBlue = {
	  50: '#e1f5fe',
	  100: '#b3e5fc',
	  200: '#81d4fa',
	  300: '#4fc3f7',
	  400: '#29b6f6',
	  500: '#03a9f4',
	  600: '#039be5',
	  700: '#0288d1',
	  800: '#0277bd',
	  900: '#01579b',
	  A100: '#80d8ff',
	  A200: '#40c4ff',
	  A400: '#00b0ff',
	  A700: '#0091ea'
	};
	var lightBlue$1 = lightBlue;

	const green = {
	  50: '#e8f5e9',
	  100: '#c8e6c9',
	  200: '#a5d6a7',
	  300: '#81c784',
	  400: '#66bb6a',
	  500: '#4caf50',
	  600: '#43a047',
	  700: '#388e3c',
	  800: '#2e7d32',
	  900: '#1b5e20',
	  A100: '#b9f6ca',
	  A200: '#69f0ae',
	  A400: '#00e676',
	  A700: '#00c853'
	};
	var green$1 = green;

	const yellow = {
	  50: '#fffde7',
	  100: '#fff9c4',
	  200: '#fff59d',
	  300: '#fff176',
	  400: '#ffee58',
	  500: '#ffeb3b',
	  600: '#fdd835',
	  700: '#fbc02d',
	  800: '#f9a825',
	  900: '#f57f17',
	  A100: '#ffff8d',
	  A200: '#ffff00',
	  A400: '#ffea00',
	  A700: '#ffd600'
	};
	var yellow$1 = yellow;

	const orange = {
	  50: '#fff3e0',
	  100: '#ffe0b2',
	  200: '#ffcc80',
	  300: '#ffb74d',
	  400: '#ffa726',
	  500: '#ff9800',
	  600: '#fb8c00',
	  700: '#f57c00',
	  800: '#ef6c00',
	  900: '#e65100',
	  A100: '#ffd180',
	  A200: '#ffab40',
	  A400: '#ff9100',
	  A700: '#ff6d00'
	};
	var orange$1 = orange;

	const grey = {
	  50: '#fafafa',
	  100: '#f5f5f5',
	  200: '#eeeeee',
	  300: '#e0e0e0',
	  400: '#bdbdbd',
	  500: '#9e9e9e',
	  600: '#757575',
	  700: '#616161',
	  800: '#424242',
	  900: '#212121',
	  A100: '#f5f5f5',
	  A200: '#eeeeee',
	  A400: '#bdbdbd',
	  A700: '#616161'
	};
	var grey$1 = grey;

	/**
	 * WARNING: Don't import this directly.
	 * Use `MuiError` from `@mui/internal-babel-macros/MuiError.macro` instead.
	 * @param {number} code
	 */
	function formatMuiErrorMessage$1(code) {
	  // Apply babel-plugin-transform-template-literals in loose mode
	  // loose mode is safe if we're concatenating primitives
	  // see https://babeljs.io/docs/en/babel-plugin-transform-template-literals#loose
	  /* eslint-disable prefer-template */
	  let url = 'https://mui.com/production-error/?code=' + code;
	  for (let i = 1; i < arguments.length; i += 1) {
	    // rest params over-transpile for this case
	    // eslint-disable-next-line prefer-rest-params
	    url += '&args[]=' + encodeURIComponent(arguments[i]);
	  }
	  return 'Minified MUI error #' + code + '; visit ' + url + ' for the full message.';
	  /* eslint-enable prefer-template */
	}

	var formatMuiErrorMessage = /*#__PURE__*/Object.freeze({
		__proto__: null,
		default: formatMuiErrorMessage$1
	});

	var THEME_ID = '$$material';

	function _extends$1() {
	  return _extends$1 = Object.assign ? Object.assign.bind() : function (n) {
	    for (var e = 1; e < arguments.length; e++) {
	      var t = arguments[e];
	      for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]);
	    }
	    return n;
	  }, _extends$1.apply(null, arguments);
	}

	function _objectWithoutPropertiesLoose(r, e) {
	  if (null == r) return {};
	  var t = {};
	  for (var n in r) if ({}.hasOwnProperty.call(r, n)) {
	    if (-1 !== e.indexOf(n)) continue;
	    t[n] = r[n];
	  }
	  return t;
	}

	var reactExports = requireReact();
	var React = /*@__PURE__*/getDefaultExportFromCjs(reactExports);

	var React$1 = /*#__PURE__*/_mergeNamespaces({
		__proto__: null,
		default: React
	}, [reactExports]);

	function memoize$1(fn) {
	  var cache = Object.create(null);
	  return function (arg) {
	    if (cache[arg] === undefined) cache[arg] = fn(arg);
	    return cache[arg];
	  };
	}

	var reactPropsRegex = /^((children|dangerouslySetInnerHTML|key|ref|autoFocus|defaultValue|defaultChecked|innerHTML|suppressContentEditableWarning|suppressHydrationWarning|valueLink|abbr|accept|acceptCharset|accessKey|action|allow|allowUserMedia|allowPaymentRequest|allowFullScreen|allowTransparency|alt|async|autoComplete|autoPlay|capture|cellPadding|cellSpacing|challenge|charSet|checked|cite|classID|className|cols|colSpan|content|contentEditable|contextMenu|controls|controlsList|coords|crossOrigin|data|dateTime|decoding|default|defer|dir|disabled|disablePictureInPicture|disableRemotePlayback|download|draggable|encType|enterKeyHint|form|formAction|formEncType|formMethod|formNoValidate|formTarget|frameBorder|headers|height|hidden|high|href|hrefLang|htmlFor|httpEquiv|id|inputMode|integrity|is|keyParams|keyType|kind|label|lang|list|loading|loop|low|marginHeight|marginWidth|max|maxLength|media|mediaGroup|method|min|minLength|multiple|muted|name|nonce|noValidate|open|optimum|pattern|placeholder|playsInline|poster|preload|profile|radioGroup|readOnly|referrerPolicy|rel|required|reversed|role|rows|rowSpan|sandbox|scope|scoped|scrolling|seamless|selected|shape|size|sizes|slot|span|spellCheck|src|srcDoc|srcLang|srcSet|start|step|style|summary|tabIndex|target|title|translate|type|useMap|value|width|wmode|wrap|about|datatype|inlist|prefix|property|resource|typeof|vocab|autoCapitalize|autoCorrect|autoSave|color|incremental|fallback|inert|itemProp|itemScope|itemType|itemID|itemRef|on|option|results|security|unselectable|accentHeight|accumulate|additive|alignmentBaseline|allowReorder|alphabetic|amplitude|arabicForm|ascent|attributeName|attributeType|autoReverse|azimuth|baseFrequency|baselineShift|baseProfile|bbox|begin|bias|by|calcMode|capHeight|clip|clipPathUnits|clipPath|clipRule|colorInterpolation|colorInterpolationFilters|colorProfile|colorRendering|contentScriptType|contentStyleType|cursor|cx|cy|d|decelerate|descent|diffuseConstant|direction|display|divisor|dominantBaseline|dur|dx|dy|edgeMode|elevation|enableBackground|end|exponent|externalResourcesRequired|fill|fillOpacity|fillRule|filter|filterRes|filterUnits|floodColor|floodOpacity|focusable|fontFamily|fontSize|fontSizeAdjust|fontStretch|fontStyle|fontVariant|fontWeight|format|from|fr|fx|fy|g1|g2|glyphName|glyphOrientationHorizontal|glyphOrientationVertical|glyphRef|gradientTransform|gradientUnits|hanging|horizAdvX|horizOriginX|ideographic|imageRendering|in|in2|intercept|k|k1|k2|k3|k4|kernelMatrix|kernelUnitLength|kerning|keyPoints|keySplines|keyTimes|lengthAdjust|letterSpacing|lightingColor|limitingConeAngle|local|markerEnd|markerMid|markerStart|markerHeight|markerUnits|markerWidth|mask|maskContentUnits|maskUnits|mathematical|mode|numOctaves|offset|opacity|operator|order|orient|orientation|origin|overflow|overlinePosition|overlineThickness|panose1|paintOrder|pathLength|patternContentUnits|patternTransform|patternUnits|pointerEvents|points|pointsAtX|pointsAtY|pointsAtZ|preserveAlpha|preserveAspectRatio|primitiveUnits|r|radius|refX|refY|renderingIntent|repeatCount|repeatDur|requiredExtensions|requiredFeatures|restart|result|rotate|rx|ry|scale|seed|shapeRendering|slope|spacing|specularConstant|specularExponent|speed|spreadMethod|startOffset|stdDeviation|stemh|stemv|stitchTiles|stopColor|stopOpacity|strikethroughPosition|strikethroughThickness|string|stroke|strokeDasharray|strokeDashoffset|strokeLinecap|strokeLinejoin|strokeMiterlimit|strokeOpacity|strokeWidth|surfaceScale|systemLanguage|tableValues|targetX|targetY|textAnchor|textDecoration|textRendering|textLength|to|transform|u1|u2|underlinePosition|underlineThickness|unicode|unicodeBidi|unicodeRange|unitsPerEm|vAlphabetic|vHanging|vIdeographic|vMathematical|values|vectorEffect|version|vertAdvY|vertOriginX|vertOriginY|viewBox|viewTarget|visibility|widths|wordSpacing|writingMode|x|xHeight|x1|x2|xChannelSelector|xlinkActuate|xlinkArcrole|xlinkHref|xlinkRole|xlinkShow|xlinkTitle|xlinkType|xmlBase|xmlns|xmlnsXlink|xmlLang|xmlSpace|y|y1|y2|yChannelSelector|z|zoomAndPan|for|class|autofocus)|(([Dd][Aa][Tt][Aa]|[Aa][Rr][Ii][Aa]|x)-.*))$/; // https://esbench.com/bench/5bfee68a4cd7e6009ef61d23

	var isPropValid = /* #__PURE__ */memoize$1(function (prop) {
	  return reactPropsRegex.test(prop) || prop.charCodeAt(0) === 111
	  /* o */ && prop.charCodeAt(1) === 110
	  /* n */ && prop.charCodeAt(2) < 91;
	}
	/* Z+1 */);

	/*

	Based off glamor's StyleSheet, thanks Sunil ❤️

	high performance StyleSheet for css-in-js systems

	- uses multiple style tags behind the scenes for millions of rules
	- uses `insertRule` for appending in production for *much* faster performance

	// usage

	import { StyleSheet } from '@emotion/sheet'

	let styleSheet = new StyleSheet({ key: '', container: document.head })

	styleSheet.insert('#box { border: 1px solid red; }')
	- appends a css rule into the stylesheet

	styleSheet.flush()
	- empties the stylesheet of all its contents

	*/
	// $FlowFixMe
	function sheetForTag(tag) {
	  if (tag.sheet) {
	    // $FlowFixMe
	    return tag.sheet;
	  } // this weirdness brought to you by firefox

	  /* istanbul ignore next */

	  for (var i = 0; i < document.styleSheets.length; i++) {
	    if (document.styleSheets[i].ownerNode === tag) {
	      // $FlowFixMe
	      return document.styleSheets[i];
	    }
	  }
	}
	function createStyleElement(options) {
	  var tag = document.createElement('style');
	  tag.setAttribute('data-emotion', options.key);
	  if (options.nonce !== undefined) {
	    tag.setAttribute('nonce', options.nonce);
	  }
	  tag.appendChild(document.createTextNode(''));
	  tag.setAttribute('data-s', '');
	  return tag;
	}
	var StyleSheet = /*#__PURE__*/function () {
	  // Using Node instead of HTMLElement since container may be a ShadowRoot
	  function StyleSheet(options) {
	    var _this = this;
	    this._insertTag = function (tag) {
	      var before;
	      if (_this.tags.length === 0) {
	        if (_this.insertionPoint) {
	          before = _this.insertionPoint.nextSibling;
	        } else if (_this.prepend) {
	          before = _this.container.firstChild;
	        } else {
	          before = _this.before;
	        }
	      } else {
	        before = _this.tags[_this.tags.length - 1].nextSibling;
	      }
	      _this.container.insertBefore(tag, before);
	      _this.tags.push(tag);
	    };
	    this.isSpeedy = options.speedy === undefined ? "production" === 'production' : options.speedy;
	    this.tags = [];
	    this.ctr = 0;
	    this.nonce = options.nonce; // key is the value of the data-emotion attribute, it's used to identify different sheets

	    this.key = options.key;
	    this.container = options.container;
	    this.prepend = options.prepend;
	    this.insertionPoint = options.insertionPoint;
	    this.before = null;
	  }
	  var _proto = StyleSheet.prototype;
	  _proto.hydrate = function hydrate(nodes) {
	    nodes.forEach(this._insertTag);
	  };
	  _proto.insert = function insert(rule) {
	    // the max length is how many rules we have per style tag, it's 65000 in speedy mode
	    // it's 1 in dev because we insert source maps that map a single rule to a location
	    // and you can only have one source map per style tag
	    if (this.ctr % (this.isSpeedy ? 65000 : 1) === 0) {
	      this._insertTag(createStyleElement(this));
	    }
	    var tag = this.tags[this.tags.length - 1];
	    if (this.isSpeedy) {
	      var sheet = sheetForTag(tag);
	      try {
	        // this is the ultrafast version, works across browsers
	        // the big drawback is that the css won't be editable in devtools
	        sheet.insertRule(rule, sheet.cssRules.length);
	      } catch (e) {
	      }
	    } else {
	      tag.appendChild(document.createTextNode(rule));
	    }
	    this.ctr++;
	  };
	  _proto.flush = function flush() {
	    // $FlowFixMe
	    this.tags.forEach(function (tag) {
	      return tag.parentNode && tag.parentNode.removeChild(tag);
	    });
	    this.tags = [];
	    this.ctr = 0;
	  };
	  return StyleSheet;
	}();

	var MS = '-ms-';
	var MOZ = '-moz-';
	var WEBKIT = '-webkit-';
	var COMMENT = 'comm';
	var RULESET = 'rule';
	var DECLARATION = 'decl';
	var IMPORT = '@import';
	var KEYFRAMES = '@keyframes';
	var LAYER = '@layer';

	/**
	 * @param {number}
	 * @return {number}
	 */
	var abs = Math.abs;

	/**
	 * @param {number}
	 * @return {string}
	 */
	var from = String.fromCharCode;

	/**
	 * @param {object}
	 * @return {object}
	 */
	var assign = Object.assign;

	/**
	 * @param {string} value
	 * @param {number} length
	 * @return {number}
	 */
	function hash(value, length) {
	  return charat(value, 0) ^ 45 ? (((length << 2 ^ charat(value, 0)) << 2 ^ charat(value, 1)) << 2 ^ charat(value, 2)) << 2 ^ charat(value, 3) : 0;
	}

	/**
	 * @param {string} value
	 * @return {string}
	 */
	function trim(value) {
	  return value.trim();
	}

	/**
	 * @param {string} value
	 * @param {RegExp} pattern
	 * @return {string?}
	 */
	function match(value, pattern) {
	  return (value = pattern.exec(value)) ? value[0] : value;
	}

	/**
	 * @param {string} value
	 * @param {(string|RegExp)} pattern
	 * @param {string} replacement
	 * @return {string}
	 */
	function replace(value, pattern, replacement) {
	  return value.replace(pattern, replacement);
	}

	/**
	 * @param {string} value
	 * @param {string} search
	 * @return {number}
	 */
	function indexof(value, search) {
	  return value.indexOf(search);
	}

	/**
	 * @param {string} value
	 * @param {number} index
	 * @return {number}
	 */
	function charat(value, index) {
	  return value.charCodeAt(index) | 0;
	}

	/**
	 * @param {string} value
	 * @param {number} begin
	 * @param {number} end
	 * @return {string}
	 */
	function substr(value, begin, end) {
	  return value.slice(begin, end);
	}

	/**
	 * @param {string} value
	 * @return {number}
	 */
	function strlen(value) {
	  return value.length;
	}

	/**
	 * @param {any[]} value
	 * @return {number}
	 */
	function sizeof(value) {
	  return value.length;
	}

	/**
	 * @param {any} value
	 * @param {any[]} array
	 * @return {any}
	 */
	function append(value, array) {
	  return array.push(value), value;
	}

	/**
	 * @param {string[]} array
	 * @param {function} callback
	 * @return {string}
	 */
	function combine(array, callback) {
	  return array.map(callback).join('');
	}

	var line = 1;
	var column = 1;
	var length = 0;
	var position = 0;
	var character = 0;
	var characters = '';

	/**
	 * @param {string} value
	 * @param {object | null} root
	 * @param {object | null} parent
	 * @param {string} type
	 * @param {string[] | string} props
	 * @param {object[] | string} children
	 * @param {number} length
	 */
	function node(value, root, parent, type, props, children, length) {
	  return {
	    value: value,
	    root: root,
	    parent: parent,
	    type: type,
	    props: props,
	    children: children,
	    line: line,
	    column: column,
	    length: length,
	    return: ''
	  };
	}

	/**
	 * @param {object} root
	 * @param {object} props
	 * @return {object}
	 */
	function copy$1(root, props) {
	  return assign(node('', null, null, '', null, null, 0), root, {
	    length: -root.length
	  }, props);
	}

	/**
	 * @return {number}
	 */
	function char() {
	  return character;
	}

	/**
	 * @return {number}
	 */
	function prev() {
	  character = position > 0 ? charat(characters, --position) : 0;
	  if (column--, character === 10) column = 1, line--;
	  return character;
	}

	/**
	 * @return {number}
	 */
	function next() {
	  character = position < length ? charat(characters, position++) : 0;
	  if (column++, character === 10) column = 1, line++;
	  return character;
	}

	/**
	 * @return {number}
	 */
	function peek() {
	  return charat(characters, position);
	}

	/**
	 * @return {number}
	 */
	function caret() {
	  return position;
	}

	/**
	 * @param {number} begin
	 * @param {number} end
	 * @return {string}
	 */
	function slice$1(begin, end) {
	  return substr(characters, begin, end);
	}

	/**
	 * @param {number} type
	 * @return {number}
	 */
	function token(type) {
	  switch (type) {
	    // \0 \t \n \r \s whitespace token
	    case 0:
	    case 9:
	    case 10:
	    case 13:
	    case 32:
	      return 5;
	    // ! + , / > @ ~ isolate token
	    case 33:
	    case 43:
	    case 44:
	    case 47:
	    case 62:
	    case 64:
	    case 126:
	    // ; { } breakpoint token
	    case 59:
	    case 123:
	    case 125:
	      return 4;
	    // : accompanied token
	    case 58:
	      return 3;
	    // " ' ( [ opening delimit token
	    case 34:
	    case 39:
	    case 40:
	    case 91:
	      return 2;
	    // ) ] closing delimit token
	    case 41:
	    case 93:
	      return 1;
	  }
	  return 0;
	}

	/**
	 * @param {string} value
	 * @return {any[]}
	 */
	function alloc(value) {
	  return line = column = 1, length = strlen(characters = value), position = 0, [];
	}

	/**
	 * @param {any} value
	 * @return {any}
	 */
	function dealloc(value) {
	  return characters = '', value;
	}

	/**
	 * @param {number} type
	 * @return {string}
	 */
	function delimit(type) {
	  return trim(slice$1(position - 1, delimiter(type === 91 ? type + 2 : type === 40 ? type + 1 : type)));
	}

	/**
	 * @param {number} type
	 * @return {string}
	 */
	function whitespace(type) {
	  while (character = peek()) if (character < 33) next();else break;
	  return token(type) > 2 || token(character) > 3 ? '' : ' ';
	}

	/**
	 * @param {number} index
	 * @param {number} count
	 * @return {string}
	 */
	function escaping(index, count) {
	  while (--count && next())
	  // not 0-9 A-F a-f
	  if (character < 48 || character > 102 || character > 57 && character < 65 || character > 70 && character < 97) break;
	  return slice$1(index, caret() + (count < 6 && peek() == 32 && next() == 32));
	}

	/**
	 * @param {number} type
	 * @return {number}
	 */
	function delimiter(type) {
	  while (next()) switch (character) {
	    // ] ) " '
	    case type:
	      return position;
	    // " '
	    case 34:
	    case 39:
	      if (type !== 34 && type !== 39) delimiter(character);
	      break;
	    // (
	    case 40:
	      if (type === 41) delimiter(type);
	      break;
	    // \
	    case 92:
	      next();
	      break;
	  }
	  return position;
	}

	/**
	 * @param {number} type
	 * @param {number} index
	 * @return {number}
	 */
	function commenter(type, index) {
	  while (next())
	  // //
	  if (type + character === 47 + 10) break;
	  // /*
	  else if (type + character === 42 + 42 && peek() === 47) break;
	  return '/*' + slice$1(index, position - 1) + '*' + from(type === 47 ? type : next());
	}

	/**
	 * @param {number} index
	 * @return {string}
	 */
	function identifier(index) {
	  while (!token(peek())) next();
	  return slice$1(index, position);
	}

	/**
	 * @param {string} value
	 * @return {object[]}
	 */
	function compile(value) {
	  return dealloc(parse('', null, null, null, [''], value = alloc(value), 0, [0], value));
	}

	/**
	 * @param {string} value
	 * @param {object} root
	 * @param {object?} parent
	 * @param {string[]} rule
	 * @param {string[]} rules
	 * @param {string[]} rulesets
	 * @param {number[]} pseudo
	 * @param {number[]} points
	 * @param {string[]} declarations
	 * @return {object}
	 */
	function parse(value, root, parent, rule, rules, rulesets, pseudo, points, declarations) {
	  var index = 0;
	  var offset = 0;
	  var length = pseudo;
	  var atrule = 0;
	  var property = 0;
	  var previous = 0;
	  var variable = 1;
	  var scanning = 1;
	  var ampersand = 1;
	  var character = 0;
	  var type = '';
	  var props = rules;
	  var children = rulesets;
	  var reference = rule;
	  var characters = type;
	  while (scanning) switch (previous = character, character = next()) {
	    // (
	    case 40:
	      if (previous != 108 && charat(characters, length - 1) == 58) {
	        if (indexof(characters += replace(delimit(character), '&', '&\f'), '&\f') != -1) ampersand = -1;
	        break;
	      }
	    // " ' [
	    case 34:
	    case 39:
	    case 91:
	      characters += delimit(character);
	      break;
	    // \t \n \r \s
	    case 9:
	    case 10:
	    case 13:
	    case 32:
	      characters += whitespace(previous);
	      break;
	    // \
	    case 92:
	      characters += escaping(caret() - 1, 7);
	      continue;
	    // /
	    case 47:
	      switch (peek()) {
	        case 42:
	        case 47:
	          append(comment(commenter(next(), caret()), root, parent), declarations);
	          break;
	        default:
	          characters += '/';
	      }
	      break;
	    // {
	    case 123 * variable:
	      points[index++] = strlen(characters) * ampersand;
	    // } ; \0
	    case 125 * variable:
	    case 59:
	    case 0:
	      switch (character) {
	        // \0 }
	        case 0:
	        case 125:
	          scanning = 0;
	        // ;
	        case 59 + offset:
	          if (ampersand == -1) characters = replace(characters, /\f/g, '');
	          if (property > 0 && strlen(characters) - length) append(property > 32 ? declaration(characters + ';', rule, parent, length - 1) : declaration(replace(characters, ' ', '') + ';', rule, parent, length - 2), declarations);
	          break;
	        // @ ;
	        case 59:
	          characters += ';';
	        // { rule/at-rule
	        default:
	          append(reference = ruleset(characters, root, parent, index, offset, rules, points, type, props = [], children = [], length), rulesets);
	          if (character === 123) if (offset === 0) parse(characters, root, reference, reference, props, rulesets, length, points, children);else switch (atrule === 99 && charat(characters, 3) === 110 ? 100 : atrule) {
	            // d l m s
	            case 100:
	            case 108:
	            case 109:
	            case 115:
	              parse(value, reference, reference, rule && append(ruleset(value, reference, reference, 0, 0, rules, points, type, rules, props = [], length), children), rules, children, length, points, rule ? props : children);
	              break;
	            default:
	              parse(characters, reference, reference, reference, [''], children, 0, points, children);
	          }
	      }
	      index = offset = property = 0, variable = ampersand = 1, type = characters = '', length = pseudo;
	      break;
	    // :
	    case 58:
	      length = 1 + strlen(characters), property = previous;
	    default:
	      if (variable < 1) if (character == 123) --variable;else if (character == 125 && variable++ == 0 && prev() == 125) continue;
	      switch (characters += from(character), character * variable) {
	        // &
	        case 38:
	          ampersand = offset > 0 ? 1 : (characters += '\f', -1);
	          break;
	        // ,
	        case 44:
	          points[index++] = (strlen(characters) - 1) * ampersand, ampersand = 1;
	          break;
	        // @
	        case 64:
	          // -
	          if (peek() === 45) characters += delimit(next());
	          atrule = peek(), offset = length = strlen(type = characters += identifier(caret())), character++;
	          break;
	        // -
	        case 45:
	          if (previous === 45 && strlen(characters) == 2) variable = 0;
	      }
	  }
	  return rulesets;
	}

	/**
	 * @param {string} value
	 * @param {object} root
	 * @param {object?} parent
	 * @param {number} index
	 * @param {number} offset
	 * @param {string[]} rules
	 * @param {number[]} points
	 * @param {string} type
	 * @param {string[]} props
	 * @param {string[]} children
	 * @param {number} length
	 * @return {object}
	 */
	function ruleset(value, root, parent, index, offset, rules, points, type, props, children, length) {
	  var post = offset - 1;
	  var rule = offset === 0 ? rules : [''];
	  var size = sizeof(rule);
	  for (var i = 0, j = 0, k = 0; i < index; ++i) for (var x = 0, y = substr(value, post + 1, post = abs(j = points[i])), z = value; x < size; ++x) if (z = trim(j > 0 ? rule[x] + ' ' + y : replace(y, /&\f/g, rule[x]))) props[k++] = z;
	  return node(value, root, parent, offset === 0 ? RULESET : type, props, children, length);
	}

	/**
	 * @param {number} value
	 * @param {object} root
	 * @param {object?} parent
	 * @return {object}
	 */
	function comment(value, root, parent) {
	  return node(value, root, parent, COMMENT, from(char()), substr(value, 2, -2), 0);
	}

	/**
	 * @param {string} value
	 * @param {object} root
	 * @param {object?} parent
	 * @param {number} length
	 * @return {object}
	 */
	function declaration(value, root, parent, length) {
	  return node(value, root, parent, DECLARATION, substr(value, 0, length), substr(value, length + 1, -1), length);
	}

	/**
	 * @param {object[]} children
	 * @param {function} callback
	 * @return {string}
	 */
	function serialize(children, callback) {
	  var output = '';
	  var length = sizeof(children);
	  for (var i = 0; i < length; i++) output += callback(children[i], i, children, callback) || '';
	  return output;
	}

	/**
	 * @param {object} element
	 * @param {number} index
	 * @param {object[]} children
	 * @param {function} callback
	 * @return {string}
	 */
	function stringify(element, index, children, callback) {
	  switch (element.type) {
	    case LAYER:
	      if (element.children.length) break;
	    case IMPORT:
	    case DECLARATION:
	      return element.return = element.return || element.value;
	    case COMMENT:
	      return '';
	    case KEYFRAMES:
	      return element.return = element.value + '{' + serialize(element.children, callback) + '}';
	    case RULESET:
	      element.value = element.props.join(',');
	  }
	  return strlen(children = serialize(element.children, callback)) ? element.return = element.value + '{' + children + '}' : '';
	}

	/**
	 * @param {function[]} collection
	 * @return {function}
	 */
	function middleware(collection) {
	  var length = sizeof(collection);
	  return function (element, index, children, callback) {
	    var output = '';
	    for (var i = 0; i < length; i++) output += collection[i](element, index, children, callback) || '';
	    return output;
	  };
	}

	/**
	 * @param {function} callback
	 * @return {function}
	 */
	function rulesheet(callback) {
	  return function (element) {
	    if (!element.root) if (element = element.return) callback(element);
	  };
	}

	var identifierWithPointTracking = function identifierWithPointTracking(begin, points, index) {
	  var previous = 0;
	  var character = 0;
	  while (true) {
	    previous = character;
	    character = peek(); // &\f

	    if (previous === 38 && character === 12) {
	      points[index] = 1;
	    }
	    if (token(character)) {
	      break;
	    }
	    next();
	  }
	  return slice$1(begin, position);
	};
	var toRules = function toRules(parsed, points) {
	  // pretend we've started with a comma
	  var index = -1;
	  var character = 44;
	  do {
	    switch (token(character)) {
	      case 0:
	        // &\f
	        if (character === 38 && peek() === 12) {
	          // this is not 100% correct, we don't account for literal sequences here - like for example quoted strings
	          // stylis inserts \f after & to know when & where it should replace this sequence with the context selector
	          // and when it should just concatenate the outer and inner selectors
	          // it's very unlikely for this sequence to actually appear in a different context, so we just leverage this fact here
	          points[index] = 1;
	        }
	        parsed[index] += identifierWithPointTracking(position - 1, points, index);
	        break;
	      case 2:
	        parsed[index] += delimit(character);
	        break;
	      case 4:
	        // comma
	        if (character === 44) {
	          // colon
	          parsed[++index] = peek() === 58 ? '&\f' : '';
	          points[index] = parsed[index].length;
	          break;
	        }

	      // fallthrough

	      default:
	        parsed[index] += from(character);
	    }
	  } while (character = next());
	  return parsed;
	};
	var getRules = function getRules(value, points) {
	  return dealloc(toRules(alloc(value), points));
	}; // WeakSet would be more appropriate, but only WeakMap is supported in IE11

	var fixedElements = /* #__PURE__ */new WeakMap();
	var compat = function compat(element) {
	  if (element.type !== 'rule' || !element.parent ||
	  // positive .length indicates that this rule contains pseudo
	  // negative .length indicates that this rule has been already prefixed
	  element.length < 1) {
	    return;
	  }
	  var value = element.value,
	    parent = element.parent;
	  var isImplicitRule = element.column === parent.column && element.line === parent.line;
	  while (parent.type !== 'rule') {
	    parent = parent.parent;
	    if (!parent) return;
	  } // short-circuit for the simplest case

	  if (element.props.length === 1 && value.charCodeAt(0) !== 58
	  /* colon */ && !fixedElements.get(parent)) {
	    return;
	  } // if this is an implicitly inserted rule (the one eagerly inserted at the each new nested level)
	  // then the props has already been manipulated beforehand as they that array is shared between it and its "rule parent"

	  if (isImplicitRule) {
	    return;
	  }
	  fixedElements.set(element, true);
	  var points = [];
	  var rules = getRules(value, points);
	  var parentRules = parent.props;
	  for (var i = 0, k = 0; i < rules.length; i++) {
	    for (var j = 0; j < parentRules.length; j++, k++) {
	      element.props[k] = points[i] ? rules[i].replace(/&\f/g, parentRules[j]) : parentRules[j] + " " + rules[i];
	    }
	  }
	};
	var removeLabel = function removeLabel(element) {
	  if (element.type === 'decl') {
	    var value = element.value;
	    if (
	    // charcode for l
	    value.charCodeAt(0) === 108 &&
	    // charcode for b
	    value.charCodeAt(2) === 98) {
	      // this ignores label
	      element["return"] = '';
	      element.value = '';
	    }
	  }
	};

	/* eslint-disable no-fallthrough */

	function prefix(value, length) {
	  switch (hash(value, length)) {
	    // color-adjust
	    case 5103:
	      return WEBKIT + 'print-' + value + value;
	    // animation, animation-(delay|direction|duration|fill-mode|iteration-count|name|play-state|timing-function)

	    case 5737:
	    case 4201:
	    case 3177:
	    case 3433:
	    case 1641:
	    case 4457:
	    case 2921: // text-decoration, filter, clip-path, backface-visibility, column, box-decoration-break

	    case 5572:
	    case 6356:
	    case 5844:
	    case 3191:
	    case 6645:
	    case 3005: // mask, mask-image, mask-(mode|clip|size), mask-(repeat|origin), mask-position, mask-composite,

	    case 6391:
	    case 5879:
	    case 5623:
	    case 6135:
	    case 4599:
	    case 4855: // background-clip, columns, column-(count|fill|gap|rule|rule-color|rule-style|rule-width|span|width)

	    case 4215:
	    case 6389:
	    case 5109:
	    case 5365:
	    case 5621:
	    case 3829:
	      return WEBKIT + value + value;
	    // appearance, user-select, transform, hyphens, text-size-adjust

	    case 5349:
	    case 4246:
	    case 4810:
	    case 6968:
	    case 2756:
	      return WEBKIT + value + MOZ + value + MS + value + value;
	    // flex, flex-direction

	    case 6828:
	    case 4268:
	      return WEBKIT + value + MS + value + value;
	    // order

	    case 6165:
	      return WEBKIT + value + MS + 'flex-' + value + value;
	    // align-items

	    case 5187:
	      return WEBKIT + value + replace(value, /(\w+).+(:[^]+)/, WEBKIT + 'box-$1$2' + MS + 'flex-$1$2') + value;
	    // align-self

	    case 5443:
	      return WEBKIT + value + MS + 'flex-item-' + replace(value, /flex-|-self/, '') + value;
	    // align-content

	    case 4675:
	      return WEBKIT + value + MS + 'flex-line-pack' + replace(value, /align-content|flex-|-self/, '') + value;
	    // flex-shrink

	    case 5548:
	      return WEBKIT + value + MS + replace(value, 'shrink', 'negative') + value;
	    // flex-basis

	    case 5292:
	      return WEBKIT + value + MS + replace(value, 'basis', 'preferred-size') + value;
	    // flex-grow

	    case 6060:
	      return WEBKIT + 'box-' + replace(value, '-grow', '') + WEBKIT + value + MS + replace(value, 'grow', 'positive') + value;
	    // transition

	    case 4554:
	      return WEBKIT + replace(value, /([^-])(transform)/g, '$1' + WEBKIT + '$2') + value;
	    // cursor

	    case 6187:
	      return replace(replace(replace(value, /(zoom-|grab)/, WEBKIT + '$1'), /(image-set)/, WEBKIT + '$1'), value, '') + value;
	    // background, background-image

	    case 5495:
	    case 3959:
	      return replace(value, /(image-set\([^]*)/, WEBKIT + '$1' + '$`$1');
	    // justify-content

	    case 4968:
	      return replace(replace(value, /(.+:)(flex-)?(.*)/, WEBKIT + 'box-pack:$3' + MS + 'flex-pack:$3'), /s.+-b[^;]+/, 'justify') + WEBKIT + value + value;
	    // (margin|padding)-inline-(start|end)

	    case 4095:
	    case 3583:
	    case 4068:
	    case 2532:
	      return replace(value, /(.+)-inline(.+)/, WEBKIT + '$1$2') + value;
	    // (min|max)?(width|height|inline-size|block-size)

	    case 8116:
	    case 7059:
	    case 5753:
	    case 5535:
	    case 5445:
	    case 5701:
	    case 4933:
	    case 4677:
	    case 5533:
	    case 5789:
	    case 5021:
	    case 4765:
	      // stretch, max-content, min-content, fill-available
	      if (strlen(value) - 1 - length > 6) switch (charat(value, length + 1)) {
	        // (m)ax-content, (m)in-content
	        case 109:
	          // -
	          if (charat(value, length + 4) !== 45) break;
	        // (f)ill-available, (f)it-content

	        case 102:
	          return replace(value, /(.+:)(.+)-([^]+)/, '$1' + WEBKIT + '$2-$3' + '$1' + MOZ + (charat(value, length + 3) == 108 ? '$3' : '$2-$3')) + value;
	        // (s)tretch

	        case 115:
	          return ~indexof(value, 'stretch') ? prefix(replace(value, 'stretch', 'fill-available'), length) + value : value;
	      }
	      break;
	    // position: sticky

	    case 4949:
	      // (s)ticky?
	      if (charat(value, length + 1) !== 115) break;
	    // display: (flex|inline-flex)

	    case 6444:
	      switch (charat(value, strlen(value) - 3 - (~indexof(value, '!important') && 10))) {
	        // stic(k)y
	        case 107:
	          return replace(value, ':', ':' + WEBKIT) + value;
	        // (inline-)?fl(e)x

	        case 101:
	          return replace(value, /(.+:)([^;!]+)(;|!.+)?/, '$1' + WEBKIT + (charat(value, 14) === 45 ? 'inline-' : '') + 'box$3' + '$1' + WEBKIT + '$2$3' + '$1' + MS + '$2box$3') + value;
	      }
	      break;
	    // writing-mode

	    case 5936:
	      switch (charat(value, length + 11)) {
	        // vertical-l(r)
	        case 114:
	          return WEBKIT + value + MS + replace(value, /[svh]\w+-[tblr]{2}/, 'tb') + value;
	        // vertical-r(l)

	        case 108:
	          return WEBKIT + value + MS + replace(value, /[svh]\w+-[tblr]{2}/, 'tb-rl') + value;
	        // horizontal(-)tb

	        case 45:
	          return WEBKIT + value + MS + replace(value, /[svh]\w+-[tblr]{2}/, 'lr') + value;
	      }
	      return WEBKIT + value + MS + value + value;
	  }
	  return value;
	}
	var prefixer = function prefixer(element, index, children, callback) {
	  if (element.length > -1) if (!element["return"]) switch (element.type) {
	    case DECLARATION:
	      element["return"] = prefix(element.value, element.length);
	      break;
	    case KEYFRAMES:
	      return serialize([copy$1(element, {
	        value: replace(element.value, '@', '@' + WEBKIT)
	      })], callback);
	    case RULESET:
	      if (element.length) return combine(element.props, function (value) {
	        switch (match(value, /(::plac\w+|:read-\w+)/)) {
	          // :read-(only|write)
	          case ':read-only':
	          case ':read-write':
	            return serialize([copy$1(element, {
	              props: [replace(value, /:(read-\w+)/, ':' + MOZ + '$1')]
	            })], callback);
	          // :placeholder

	          case '::placeholder':
	            return serialize([copy$1(element, {
	              props: [replace(value, /:(plac\w+)/, ':' + WEBKIT + 'input-$1')]
	            }), copy$1(element, {
	              props: [replace(value, /:(plac\w+)/, ':' + MOZ + '$1')]
	            }), copy$1(element, {
	              props: [replace(value, /:(plac\w+)/, MS + 'input-$1')]
	            })], callback);
	        }
	        return '';
	      });
	  }
	};
	var defaultStylisPlugins = [prefixer];
	var createCache = function createCache(options) {
	  var key = options.key;
	  if (key === 'css') {
	    var ssrStyles = document.querySelectorAll("style[data-emotion]:not([data-s])"); // get SSRed styles out of the way of React's hydration
	    // document.head is a safe place to move them to(though note document.head is not necessarily the last place they will be)
	    // note this very very intentionally targets all style elements regardless of the key to ensure
	    // that creating a cache works inside of render of a React component

	    Array.prototype.forEach.call(ssrStyles, function (node) {
	      // we want to only move elements which have a space in the data-emotion attribute value
	      // because that indicates that it is an Emotion 11 server-side rendered style elements
	      // while we will already ignore Emotion 11 client-side inserted styles because of the :not([data-s]) part in the selector
	      // Emotion 10 client-side inserted styles did not have data-s (but importantly did not have a space in their data-emotion attributes)
	      // so checking for the space ensures that loading Emotion 11 after Emotion 10 has inserted some styles
	      // will not result in the Emotion 10 styles being destroyed
	      var dataEmotionAttribute = node.getAttribute('data-emotion');
	      if (dataEmotionAttribute.indexOf(' ') === -1) {
	        return;
	      }
	      document.head.appendChild(node);
	      node.setAttribute('data-s', '');
	    });
	  }
	  var stylisPlugins = options.stylisPlugins || defaultStylisPlugins;
	  var inserted = {};
	  var container;
	  var nodesToHydrate = [];
	  {
	    container = options.container || document.head;
	    Array.prototype.forEach.call(
	    // this means we will ignore elements which don't have a space in them which
	    // means that the style elements we're looking at are only Emotion 11 server-rendered style elements
	    document.querySelectorAll("style[data-emotion^=\"" + key + " \"]"), function (node) {
	      var attrib = node.getAttribute("data-emotion").split(' '); // $FlowFixMe

	      for (var i = 1; i < attrib.length; i++) {
	        inserted[attrib[i]] = true;
	      }
	      nodesToHydrate.push(node);
	    });
	  }
	  var _insert;
	  var omnipresentPlugins = [compat, removeLabel];
	  {
	    var currentSheet;
	    var finalizingPlugins = [stringify, rulesheet(function (rule) {
	      currentSheet.insert(rule);
	    })];
	    var serializer = middleware(omnipresentPlugins.concat(stylisPlugins, finalizingPlugins));
	    var stylis = function stylis(styles) {
	      return serialize(compile(styles), serializer);
	    };
	    _insert = function insert(selector, serialized, sheet, shouldCache) {
	      currentSheet = sheet;
	      stylis(selector ? selector + "{" + serialized.styles + "}" : serialized.styles);
	      if (shouldCache) {
	        cache.inserted[serialized.name] = true;
	      }
	    };
	  }
	  var cache = {
	    key: key,
	    sheet: new StyleSheet({
	      key: key,
	      container: container,
	      nonce: options.nonce,
	      speedy: options.speedy,
	      prepend: options.prepend,
	      insertionPoint: options.insertionPoint
	    }),
	    nonce: options.nonce,
	    inserted: inserted,
	    registered: {},
	    insert: _insert
	  };
	  cache.sheet.hydrate(nodesToHydrate);
	  return cache;
	};

	var reactIs$1 = {exports: {}};

	var reactIs_production_min$1 = {};

	/** @license React v16.13.1
	 * react-is.production.min.js
	 *
	 * Copyright (c) Facebook, Inc. and its affiliates.
	 *
	 * This source code is licensed under the MIT license found in the
	 * LICENSE file in the root directory of this source tree.
	 */

	var hasRequiredReactIs_production_min$1;

	function requireReactIs_production_min$1 () {
		if (hasRequiredReactIs_production_min$1) return reactIs_production_min$1;
		hasRequiredReactIs_production_min$1 = 1;

		var b = "function" === typeof Symbol && Symbol.for,
		  c = b ? Symbol.for("react.element") : 60103,
		  d = b ? Symbol.for("react.portal") : 60106,
		  e = b ? Symbol.for("react.fragment") : 60107,
		  f = b ? Symbol.for("react.strict_mode") : 60108,
		  g = b ? Symbol.for("react.profiler") : 60114,
		  h = b ? Symbol.for("react.provider") : 60109,
		  k = b ? Symbol.for("react.context") : 60110,
		  l = b ? Symbol.for("react.async_mode") : 60111,
		  m = b ? Symbol.for("react.concurrent_mode") : 60111,
		  n = b ? Symbol.for("react.forward_ref") : 60112,
		  p = b ? Symbol.for("react.suspense") : 60113,
		  q = b ? Symbol.for("react.suspense_list") : 60120,
		  r = b ? Symbol.for("react.memo") : 60115,
		  t = b ? Symbol.for("react.lazy") : 60116,
		  v = b ? Symbol.for("react.block") : 60121,
		  w = b ? Symbol.for("react.fundamental") : 60117,
		  x = b ? Symbol.for("react.responder") : 60118,
		  y = b ? Symbol.for("react.scope") : 60119;
		function z(a) {
		  if ("object" === typeof a && null !== a) {
		    var u = a.$$typeof;
		    switch (u) {
		      case c:
		        switch (a = a.type, a) {
		          case l:
		          case m:
		          case e:
		          case g:
		          case f:
		          case p:
		            return a;
		          default:
		            switch (a = a && a.$$typeof, a) {
		              case k:
		              case n:
		              case t:
		              case r:
		              case h:
		                return a;
		              default:
		                return u;
		            }
		        }
		      case d:
		        return u;
		    }
		  }
		}
		function A(a) {
		  return z(a) === m;
		}
		reactIs_production_min$1.AsyncMode = l;
		reactIs_production_min$1.ConcurrentMode = m;
		reactIs_production_min$1.ContextConsumer = k;
		reactIs_production_min$1.ContextProvider = h;
		reactIs_production_min$1.Element = c;
		reactIs_production_min$1.ForwardRef = n;
		reactIs_production_min$1.Fragment = e;
		reactIs_production_min$1.Lazy = t;
		reactIs_production_min$1.Memo = r;
		reactIs_production_min$1.Portal = d;
		reactIs_production_min$1.Profiler = g;
		reactIs_production_min$1.StrictMode = f;
		reactIs_production_min$1.Suspense = p;
		reactIs_production_min$1.isAsyncMode = function (a) {
		  return A(a) || z(a) === l;
		};
		reactIs_production_min$1.isConcurrentMode = A;
		reactIs_production_min$1.isContextConsumer = function (a) {
		  return z(a) === k;
		};
		reactIs_production_min$1.isContextProvider = function (a) {
		  return z(a) === h;
		};
		reactIs_production_min$1.isElement = function (a) {
		  return "object" === typeof a && null !== a && a.$$typeof === c;
		};
		reactIs_production_min$1.isForwardRef = function (a) {
		  return z(a) === n;
		};
		reactIs_production_min$1.isFragment = function (a) {
		  return z(a) === e;
		};
		reactIs_production_min$1.isLazy = function (a) {
		  return z(a) === t;
		};
		reactIs_production_min$1.isMemo = function (a) {
		  return z(a) === r;
		};
		reactIs_production_min$1.isPortal = function (a) {
		  return z(a) === d;
		};
		reactIs_production_min$1.isProfiler = function (a) {
		  return z(a) === g;
		};
		reactIs_production_min$1.isStrictMode = function (a) {
		  return z(a) === f;
		};
		reactIs_production_min$1.isSuspense = function (a) {
		  return z(a) === p;
		};
		reactIs_production_min$1.isValidElementType = function (a) {
		  return "string" === typeof a || "function" === typeof a || a === e || a === m || a === g || a === f || a === p || a === q || "object" === typeof a && null !== a && (a.$$typeof === t || a.$$typeof === r || a.$$typeof === h || a.$$typeof === k || a.$$typeof === n || a.$$typeof === w || a.$$typeof === x || a.$$typeof === y || a.$$typeof === v);
		};
		reactIs_production_min$1.typeOf = z;
		return reactIs_production_min$1;
	}

	var hasRequiredReactIs$1;

	function requireReactIs$1 () {
		if (hasRequiredReactIs$1) return reactIs$1.exports;
		hasRequiredReactIs$1 = 1;

		{
		  reactIs$1.exports = requireReactIs_production_min$1();
		}
		return reactIs$1.exports;
	}

	var hoistNonReactStatics_cjs;
	var hasRequiredHoistNonReactStatics_cjs;

	function requireHoistNonReactStatics_cjs () {
		if (hasRequiredHoistNonReactStatics_cjs) return hoistNonReactStatics_cjs;
		hasRequiredHoistNonReactStatics_cjs = 1;

		var reactIs = requireReactIs$1();

		/**
		 * Copyright 2015, Yahoo! Inc.
		 * Copyrights licensed under the New BSD License. See the accompanying LICENSE file for terms.
		 */
		var REACT_STATICS = {
		  childContextTypes: true,
		  contextType: true,
		  contextTypes: true,
		  defaultProps: true,
		  displayName: true,
		  getDefaultProps: true,
		  getDerivedStateFromError: true,
		  getDerivedStateFromProps: true,
		  mixins: true,
		  propTypes: true,
		  type: true
		};
		var KNOWN_STATICS = {
		  name: true,
		  length: true,
		  prototype: true,
		  caller: true,
		  callee: true,
		  arguments: true,
		  arity: true
		};
		var FORWARD_REF_STATICS = {
		  '$$typeof': true,
		  render: true,
		  defaultProps: true,
		  displayName: true,
		  propTypes: true
		};
		var MEMO_STATICS = {
		  '$$typeof': true,
		  compare: true,
		  defaultProps: true,
		  displayName: true,
		  propTypes: true,
		  type: true
		};
		var TYPE_STATICS = {};
		TYPE_STATICS[reactIs.ForwardRef] = FORWARD_REF_STATICS;
		TYPE_STATICS[reactIs.Memo] = MEMO_STATICS;
		function getStatics(component) {
		  // React v16.11 and below
		  if (reactIs.isMemo(component)) {
		    return MEMO_STATICS;
		  } // React v16.12 and above

		  return TYPE_STATICS[component['$$typeof']] || REACT_STATICS;
		}
		var defineProperty = Object.defineProperty;
		var getOwnPropertyNames = Object.getOwnPropertyNames;
		var getOwnPropertySymbols = Object.getOwnPropertySymbols;
		var getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
		var getPrototypeOf = Object.getPrototypeOf;
		var objectPrototype = Object.prototype;
		function hoistNonReactStatics(targetComponent, sourceComponent, blacklist) {
		  if (typeof sourceComponent !== 'string') {
		    // don't hoist over string (html) components
		    if (objectPrototype) {
		      var inheritedComponent = getPrototypeOf(sourceComponent);
		      if (inheritedComponent && inheritedComponent !== objectPrototype) {
		        hoistNonReactStatics(targetComponent, inheritedComponent, blacklist);
		      }
		    }
		    var keys = getOwnPropertyNames(sourceComponent);
		    if (getOwnPropertySymbols) {
		      keys = keys.concat(getOwnPropertySymbols(sourceComponent));
		    }
		    var targetStatics = getStatics(targetComponent);
		    var sourceStatics = getStatics(sourceComponent);
		    for (var i = 0; i < keys.length; ++i) {
		      var key = keys[i];
		      if (!KNOWN_STATICS[key] && !(blacklist && blacklist[key]) && !(sourceStatics && sourceStatics[key]) && !(targetStatics && targetStatics[key])) {
		        var descriptor = getOwnPropertyDescriptor(sourceComponent, key);
		        try {
		          // Avoid failures from read-only properties
		          defineProperty(targetComponent, key, descriptor);
		        } catch (e) {}
		      }
		    }
		  }
		  return targetComponent;
		}
		hoistNonReactStatics_cjs = hoistNonReactStatics;
		return hoistNonReactStatics_cjs;
	}

	requireHoistNonReactStatics_cjs();

	var isBrowser = "object" !== 'undefined';
	function getRegisteredStyles(registered, registeredStyles, classNames) {
	  var rawClassName = '';
	  classNames.split(' ').forEach(function (className) {
	    if (registered[className] !== undefined) {
	      registeredStyles.push(registered[className] + ";");
	    } else {
	      rawClassName += className + " ";
	    }
	  });
	  return rawClassName;
	}
	var registerStyles = function registerStyles(cache, serialized, isStringTag) {
	  var className = cache.key + "-" + serialized.name;
	  if (
	  // we only need to add the styles to the registered cache if the
	  // class name could be used further down
	  // the tree but if it's a string tag, we know it won't
	  // so we don't have to add it to registered cache.
	  // this improves memory usage since we can avoid storing the whole style string
	  (isStringTag === false ||
	  // we need to always store it if we're in compat mode and
	  // in node since emotion-server relies on whether a style is in
	  // the registered cache to know whether a style is global or not
	  // also, note that this check will be dead code eliminated in the browser
	  isBrowser === false) && cache.registered[className] === undefined) {
	    cache.registered[className] = serialized.styles;
	  }
	};
	var insertStyles = function insertStyles(cache, serialized, isStringTag) {
	  registerStyles(cache, serialized, isStringTag);
	  var className = cache.key + "-" + serialized.name;
	  if (cache.inserted[serialized.name] === undefined) {
	    var current = serialized;
	    do {
	      cache.insert(serialized === current ? "." + className : '', current, cache.sheet, true);
	      current = current.next;
	    } while (current !== undefined);
	  }
	};

	/* eslint-disable */
	// Inspired by https://github.com/garycourt/murmurhash-js
	// Ported from https://github.com/aappleby/smhasher/blob/61a0530f28277f2e850bfc39600ce61d02b518de/src/MurmurHash2.cpp#L37-L86
	function murmur2(str) {
	  // 'm' and 'r' are mixing constants generated offline.
	  // They're not really 'magic', they just happen to work well.
	  // const m = 0x5bd1e995;
	  // const r = 24;
	  // Initialize the hash
	  var h = 0; // Mix 4 bytes at a time into the hash

	  var k,
	    i = 0,
	    len = str.length;
	  for (; len >= 4; ++i, len -= 4) {
	    k = str.charCodeAt(i) & 0xff | (str.charCodeAt(++i) & 0xff) << 8 | (str.charCodeAt(++i) & 0xff) << 16 | (str.charCodeAt(++i) & 0xff) << 24;
	    k = /* Math.imul(k, m): */
	    (k & 0xffff) * 0x5bd1e995 + ((k >>> 16) * 0xe995 << 16);
	    k ^= /* k >>> r: */
	    k >>> 24;
	    h = /* Math.imul(k, m): */
	    (k & 0xffff) * 0x5bd1e995 + ((k >>> 16) * 0xe995 << 16) ^ /* Math.imul(h, m): */
	    (h & 0xffff) * 0x5bd1e995 + ((h >>> 16) * 0xe995 << 16);
	  } // Handle the last few bytes of the input array

	  switch (len) {
	    case 3:
	      h ^= (str.charCodeAt(i + 2) & 0xff) << 16;
	    case 2:
	      h ^= (str.charCodeAt(i + 1) & 0xff) << 8;
	    case 1:
	      h ^= str.charCodeAt(i) & 0xff;
	      h = /* Math.imul(h, m): */
	      (h & 0xffff) * 0x5bd1e995 + ((h >>> 16) * 0xe995 << 16);
	  } // Do a few final mixes of the hash to ensure the last few
	  // bytes are well-incorporated.

	  h ^= h >>> 13;
	  h = /* Math.imul(h, m): */
	  (h & 0xffff) * 0x5bd1e995 + ((h >>> 16) * 0xe995 << 16);
	  return ((h ^ h >>> 15) >>> 0).toString(36);
	}

	var unitlessKeys = {
	  animationIterationCount: 1,
	  aspectRatio: 1,
	  borderImageOutset: 1,
	  borderImageSlice: 1,
	  borderImageWidth: 1,
	  boxFlex: 1,
	  boxFlexGroup: 1,
	  boxOrdinalGroup: 1,
	  columnCount: 1,
	  columns: 1,
	  flex: 1,
	  flexGrow: 1,
	  flexPositive: 1,
	  flexShrink: 1,
	  flexNegative: 1,
	  flexOrder: 1,
	  gridRow: 1,
	  gridRowEnd: 1,
	  gridRowSpan: 1,
	  gridRowStart: 1,
	  gridColumn: 1,
	  gridColumnEnd: 1,
	  gridColumnSpan: 1,
	  gridColumnStart: 1,
	  msGridRow: 1,
	  msGridRowSpan: 1,
	  msGridColumn: 1,
	  msGridColumnSpan: 1,
	  fontWeight: 1,
	  lineHeight: 1,
	  opacity: 1,
	  order: 1,
	  orphans: 1,
	  tabSize: 1,
	  widows: 1,
	  zIndex: 1,
	  zoom: 1,
	  WebkitLineClamp: 1,
	  // SVG-related properties
	  fillOpacity: 1,
	  floodOpacity: 1,
	  stopOpacity: 1,
	  strokeDasharray: 1,
	  strokeDashoffset: 1,
	  strokeMiterlimit: 1,
	  strokeOpacity: 1,
	  strokeWidth: 1
	};

	var hyphenateRegex = /[A-Z]|^ms/g;
	var animationRegex = /_EMO_([^_]+?)_([^]*?)_EMO_/g;
	var isCustomProperty = function isCustomProperty(property) {
	  return property.charCodeAt(1) === 45;
	};
	var isProcessableValue = function isProcessableValue(value) {
	  return value != null && typeof value !== 'boolean';
	};
	var processStyleName = /* #__PURE__ */memoize$1(function (styleName) {
	  return isCustomProperty(styleName) ? styleName : styleName.replace(hyphenateRegex, '-$&').toLowerCase();
	});
	var processStyleValue = function processStyleValue(key, value) {
	  switch (key) {
	    case 'animation':
	    case 'animationName':
	      {
	        if (typeof value === 'string') {
	          return value.replace(animationRegex, function (match, p1, p2) {
	            cursor = {
	              name: p1,
	              styles: p2,
	              next: cursor
	            };
	            return p1;
	          });
	        }
	      }
	  }
	  if (unitlessKeys[key] !== 1 && !isCustomProperty(key) && typeof value === 'number' && value !== 0) {
	    return value + 'px';
	  }
	  return value;
	};
	var noComponentSelectorMessage = 'Component selectors can only be used in conjunction with ' + '@emotion/babel-plugin, the swc Emotion plugin, or another Emotion-aware ' + 'compiler transform.';
	function handleInterpolation(mergedProps, registered, interpolation) {
	  if (interpolation == null) {
	    return '';
	  }
	  if (interpolation.__emotion_styles !== undefined) {
	    return interpolation;
	  }
	  switch (typeof interpolation) {
	    case 'boolean':
	      {
	        return '';
	      }
	    case 'object':
	      {
	        if (interpolation.anim === 1) {
	          cursor = {
	            name: interpolation.name,
	            styles: interpolation.styles,
	            next: cursor
	          };
	          return interpolation.name;
	        }
	        if (interpolation.styles !== undefined) {
	          var next = interpolation.next;
	          if (next !== undefined) {
	            // not the most efficient thing ever but this is a pretty rare case
	            // and there will be very few iterations of this generally
	            while (next !== undefined) {
	              cursor = {
	                name: next.name,
	                styles: next.styles,
	                next: cursor
	              };
	              next = next.next;
	            }
	          }
	          var styles = interpolation.styles + ";";
	          return styles;
	        }
	        return createStringFromObject(mergedProps, registered, interpolation);
	      }
	    case 'function':
	      {
	        if (mergedProps !== undefined) {
	          var previousCursor = cursor;
	          var result = interpolation(mergedProps);
	          cursor = previousCursor;
	          return handleInterpolation(mergedProps, registered, result);
	        }
	        break;
	      }
	  } // finalize string values (regular strings and functions interpolated into css calls)

	  if (registered == null) {
	    return interpolation;
	  }
	  var cached = registered[interpolation];
	  return cached !== undefined ? cached : interpolation;
	}
	function createStringFromObject(mergedProps, registered, obj) {
	  var string = '';
	  if (Array.isArray(obj)) {
	    for (var i = 0; i < obj.length; i++) {
	      string += handleInterpolation(mergedProps, registered, obj[i]) + ";";
	    }
	  } else {
	    for (var _key in obj) {
	      var value = obj[_key];
	      if (typeof value !== 'object') {
	        if (registered != null && registered[value] !== undefined) {
	          string += _key + "{" + registered[value] + "}";
	        } else if (isProcessableValue(value)) {
	          string += processStyleName(_key) + ":" + processStyleValue(_key, value) + ";";
	        }
	      } else {
	        if (_key === 'NO_COMPONENT_SELECTOR' && "production" !== 'production') {
	          throw new Error(noComponentSelectorMessage);
	        }
	        if (Array.isArray(value) && typeof value[0] === 'string' && (registered == null || registered[value[0]] === undefined)) {
	          for (var _i = 0; _i < value.length; _i++) {
	            if (isProcessableValue(value[_i])) {
	              string += processStyleName(_key) + ":" + processStyleValue(_key, value[_i]) + ";";
	            }
	          }
	        } else {
	          var interpolated = handleInterpolation(mergedProps, registered, value);
	          switch (_key) {
	            case 'animation':
	            case 'animationName':
	              {
	                string += processStyleName(_key) + ":" + interpolated + ";";
	                break;
	              }
	            default:
	              {
	                string += _key + "{" + interpolated + "}";
	              }
	          }
	        }
	      }
	    }
	  }
	  return string;
	}
	var labelPattern = /label:\s*([^\s;\n{]+)\s*(;|$)/g;
	// keyframes are stored on the SerializedStyles object as a linked list

	var cursor;
	var serializeStyles = function serializeStyles(args, registered, mergedProps) {
	  if (args.length === 1 && typeof args[0] === 'object' && args[0] !== null && args[0].styles !== undefined) {
	    return args[0];
	  }
	  var stringMode = true;
	  var styles = '';
	  cursor = undefined;
	  var strings = args[0];
	  if (strings == null || strings.raw === undefined) {
	    stringMode = false;
	    styles += handleInterpolation(mergedProps, registered, strings);
	  } else {
	    styles += strings[0];
	  } // we start at 1 since we've already handled the first arg

	  for (var i = 1; i < args.length; i++) {
	    styles += handleInterpolation(mergedProps, registered, args[i]);
	    if (stringMode) {
	      styles += strings[i];
	    }
	  }

	  labelPattern.lastIndex = 0;
	  var identifierName = '';
	  var match; // https://esbench.com/bench/5b809c2cf2949800a0f61fb5

	  while ((match = labelPattern.exec(styles)) !== null) {
	    identifierName += '-' +
	    // $FlowFixMe we know it's not null
	    match[1];
	  }
	  var name = murmur2(styles) + identifierName;
	  return {
	    name: name,
	    styles: styles,
	    next: cursor
	  };
	};

	var syncFallback = function syncFallback(create) {
	  return create();
	};
	var useInsertionEffect = React$1['useInsertion' + 'Effect'] ? React$1['useInsertion' + 'Effect'] : false;
	var useInsertionEffectAlwaysWithSyncFallback = useInsertionEffect || syncFallback;
	var useInsertionEffectWithLayoutFallback = useInsertionEffect || reactExports.useLayoutEffect;

	var EmotionCacheContext = /* #__PURE__ */reactExports.createContext(
	// we're doing this to avoid preconstruct's dead code elimination in this one case
	// because this module is primarily intended for the browser and node
	// but it's also required in react native and similar environments sometimes
	// and we could have a special build just for that
	// but this is much easier and the native packages
	// might use a different theme context in the future anyway
	typeof HTMLElement !== 'undefined' ? /* #__PURE__ */createCache({
	  key: 'css'
	}) : null);
	var CacheProvider = EmotionCacheContext.Provider;
	var withEmotionCache = function withEmotionCache(func) {
	  // $FlowFixMe
	  return /*#__PURE__*/reactExports.forwardRef(function (props, ref) {
	    // the cache will never be null in the browser
	    var cache = reactExports.useContext(EmotionCacheContext);
	    return func(props, cache, ref);
	  });
	};
	var ThemeContext$2 = /* #__PURE__ */reactExports.createContext({});

	// initial render from browser, insertBefore context.sheet.tags[0] or if a style hasn't been inserted there yet, appendChild
	// initial client-side render from SSR, use place of hydrating tag

	var Global = /* #__PURE__ */withEmotionCache(function (props, cache) {
	  var styles = props.styles;
	  var serialized = serializeStyles([styles], undefined, reactExports.useContext(ThemeContext$2));
	  // but it is based on a constant that will never change at runtime
	  // it's effectively like having two implementations and switching them out
	  // so it's not actually breaking anything

	  var sheetRef = reactExports.useRef();
	  useInsertionEffectWithLayoutFallback(function () {
	    var key = cache.key + "-global"; // use case of https://github.com/emotion-js/emotion/issues/2675

	    var sheet = new cache.sheet.constructor({
	      key: key,
	      nonce: cache.sheet.nonce,
	      container: cache.sheet.container,
	      speedy: cache.sheet.isSpeedy
	    });
	    var rehydrating = false; // $FlowFixMe

	    var node = document.querySelector("style[data-emotion=\"" + key + " " + serialized.name + "\"]");
	    if (cache.sheet.tags.length) {
	      sheet.before = cache.sheet.tags[0];
	    }
	    if (node !== null) {
	      rehydrating = true; // clear the hash so this node won't be recognizable as rehydratable by other <Global/>s

	      node.setAttribute('data-emotion', key);
	      sheet.hydrate([node]);
	    }
	    sheetRef.current = [sheet, rehydrating];
	    return function () {
	      sheet.flush();
	    };
	  }, [cache]);
	  useInsertionEffectWithLayoutFallback(function () {
	    var sheetRefCurrent = sheetRef.current;
	    var sheet = sheetRefCurrent[0],
	      rehydrating = sheetRefCurrent[1];
	    if (rehydrating) {
	      sheetRefCurrent[1] = false;
	      return;
	    }
	    if (serialized.next !== undefined) {
	      // insert keyframes
	      insertStyles(cache, serialized.next, true);
	    }
	    if (sheet.tags.length) {
	      // if this doesn't exist then it will be null so the style element will be appended
	      var element = sheet.tags[sheet.tags.length - 1].nextElementSibling;
	      sheet.before = element;
	      sheet.flush();
	    }
	    cache.insert("", serialized, sheet, false);
	  }, [cache, serialized.name]);
	  return null;
	});
	function css() {
	  for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
	    args[_key] = arguments[_key];
	  }
	  return serializeStyles(args);
	}
	var keyframes = function keyframes() {
	  var insertable = css.apply(void 0, arguments);
	  var name = "animation-" + insertable.name; // $FlowFixMe

	  return {
	    name: name,
	    styles: "@keyframes " + name + "{" + insertable.styles + "}",
	    anim: 1,
	    toString: function toString() {
	      return "_EMO_" + this.name + "_" + this.styles + "_EMO_";
	    }
	  };
	};

	var testOmitPropsOnStringTag = isPropValid;
	var testOmitPropsOnComponent = function testOmitPropsOnComponent(key) {
	  return key !== 'theme';
	};
	var getDefaultShouldForwardProp = function getDefaultShouldForwardProp(tag) {
	  return typeof tag === 'string' &&
	  // 96 is one less than the char code
	  // for "a" so this is checking that
	  // it's a lowercase character
	  tag.charCodeAt(0) > 96 ? testOmitPropsOnStringTag : testOmitPropsOnComponent;
	};
	var composeShouldForwardProps = function composeShouldForwardProps(tag, options, isReal) {
	  var shouldForwardProp;
	  if (options) {
	    var optionsShouldForwardProp = options.shouldForwardProp;
	    shouldForwardProp = tag.__emotion_forwardProp && optionsShouldForwardProp ? function (propName) {
	      return tag.__emotion_forwardProp(propName) && optionsShouldForwardProp(propName);
	    } : optionsShouldForwardProp;
	  }
	  if (typeof shouldForwardProp !== 'function' && isReal) {
	    shouldForwardProp = tag.__emotion_forwardProp;
	  }
	  return shouldForwardProp;
	};
	var Insertion = function Insertion(_ref) {
	  var cache = _ref.cache,
	    serialized = _ref.serialized,
	    isStringTag = _ref.isStringTag;
	  registerStyles(cache, serialized, isStringTag);
	  useInsertionEffectAlwaysWithSyncFallback(function () {
	    return insertStyles(cache, serialized, isStringTag);
	  });
	  return null;
	};
	var createStyled$2 = function createStyled(tag, options) {
	  var isReal = tag.__emotion_real === tag;
	  var baseTag = isReal && tag.__emotion_base || tag;
	  var identifierName;
	  var targetClassName;
	  if (options !== undefined) {
	    identifierName = options.label;
	    targetClassName = options.target;
	  }
	  var shouldForwardProp = composeShouldForwardProps(tag, options, isReal);
	  var defaultShouldForwardProp = shouldForwardProp || getDefaultShouldForwardProp(baseTag);
	  var shouldUseAs = !defaultShouldForwardProp('as');
	  return function () {
	    var args = arguments;
	    var styles = isReal && tag.__emotion_styles !== undefined ? tag.__emotion_styles.slice(0) : [];
	    if (identifierName !== undefined) {
	      styles.push("label:" + identifierName + ";");
	    }
	    if (args[0] == null || args[0].raw === undefined) {
	      styles.push.apply(styles, args);
	    } else {
	      styles.push(args[0][0]);
	      var len = args.length;
	      var i = 1;
	      for (; i < len; i++) {
	        styles.push(args[i], args[0][i]);
	      }
	    } // $FlowFixMe: we need to cast StatelessFunctionalComponent to our PrivateStyledComponent class

	    var Styled = withEmotionCache(function (props, cache, ref) {
	      var FinalTag = shouldUseAs && props.as || baseTag;
	      var className = '';
	      var classInterpolations = [];
	      var mergedProps = props;
	      if (props.theme == null) {
	        mergedProps = {};
	        for (var key in props) {
	          mergedProps[key] = props[key];
	        }
	        mergedProps.theme = reactExports.useContext(ThemeContext$2);
	      }
	      if (typeof props.className === 'string') {
	        className = getRegisteredStyles(cache.registered, classInterpolations, props.className);
	      } else if (props.className != null) {
	        className = props.className + " ";
	      }
	      var serialized = serializeStyles(styles.concat(classInterpolations), cache.registered, mergedProps);
	      className += cache.key + "-" + serialized.name;
	      if (targetClassName !== undefined) {
	        className += " " + targetClassName;
	      }
	      var finalShouldForwardProp = shouldUseAs && shouldForwardProp === undefined ? getDefaultShouldForwardProp(FinalTag) : defaultShouldForwardProp;
	      var newProps = {};
	      for (var _key in props) {
	        if (shouldUseAs && _key === 'as') continue;
	        if (
	        // $FlowFixMe
	        finalShouldForwardProp(_key)) {
	          newProps[_key] = props[_key];
	        }
	      }
	      newProps.className = className;
	      newProps.ref = ref;
	      return /*#__PURE__*/reactExports.createElement(reactExports.Fragment, null, /*#__PURE__*/reactExports.createElement(Insertion, {
	        cache: cache,
	        serialized: serialized,
	        isStringTag: typeof FinalTag === 'string'
	      }), /*#__PURE__*/reactExports.createElement(FinalTag, newProps));
	    });
	    Styled.displayName = identifierName !== undefined ? identifierName : "Styled(" + (typeof baseTag === 'string' ? baseTag : baseTag.displayName || baseTag.name || 'Component') + ")";
	    Styled.defaultProps = tag.defaultProps;
	    Styled.__emotion_real = Styled;
	    Styled.__emotion_base = baseTag;
	    Styled.__emotion_styles = styles;
	    Styled.__emotion_forwardProp = shouldForwardProp;
	    Object.defineProperty(Styled, 'toString', {
	      value: function value() {
	        if (targetClassName === undefined && "production" !== 'production') {
	          return 'NO_COMPONENT_SELECTOR';
	        } // $FlowFixMe: coerce undefined to string

	        return "." + targetClassName;
	      }
	    });
	    Styled.withComponent = function (nextTag, nextOptions) {
	      return createStyled(nextTag, _extends$1({}, options, nextOptions, {
	        shouldForwardProp: composeShouldForwardProps(Styled, nextOptions, true)
	      })).apply(void 0, styles);
	    };
	    return Styled;
	  };
	};

	var tags = ['a', 'abbr', 'address', 'area', 'article', 'aside', 'audio', 'b', 'base', 'bdi', 'bdo', 'big', 'blockquote', 'body', 'br', 'button', 'canvas', 'caption', 'cite', 'code', 'col', 'colgroup', 'data', 'datalist', 'dd', 'del', 'details', 'dfn', 'dialog', 'div', 'dl', 'dt', 'em', 'embed', 'fieldset', 'figcaption', 'figure', 'footer', 'form', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'head', 'header', 'hgroup', 'hr', 'html', 'i', 'iframe', 'img', 'input', 'ins', 'kbd', 'keygen', 'label', 'legend', 'li', 'link', 'main', 'map', 'mark', 'marquee', 'menu', 'menuitem', 'meta', 'meter', 'nav', 'noscript', 'object', 'ol', 'optgroup', 'option', 'output', 'p', 'param', 'picture', 'pre', 'progress', 'q', 'rp', 'rt', 'ruby', 's', 'samp', 'script', 'section', 'select', 'small', 'source', 'span', 'strong', 'style', 'sub', 'summary', 'sup', 'table', 'tbody', 'td', 'textarea', 'tfoot', 'th', 'thead', 'time', 'title', 'tr', 'track', 'u', 'ul', 'var', 'video', 'wbr',
	// SVG
	'circle', 'clipPath', 'defs', 'ellipse', 'foreignObject', 'g', 'image', 'line', 'linearGradient', 'mask', 'path', 'pattern', 'polygon', 'polyline', 'radialGradient', 'rect', 'stop', 'svg', 'text', 'tspan'];
	var newStyled = createStyled$2.bind();
	tags.forEach(function (tagName) {
	  // $FlowFixMe: we can ignore this because its exposed type is defined by the CreateStyled type
	  newStyled[tagName] = newStyled(tagName);
	});

	let cache;
	if (typeof document === 'object') {
	  cache = createCache({
	    key: 'css',
	    prepend: true
	  });
	}
	function StyledEngineProvider(props) {
	  const {
	    injectFirst,
	    children
	  } = props;
	  return injectFirst && cache ? /*#__PURE__*/jsxRuntimeExports.jsx(CacheProvider, {
	    value: cache,
	    children: children
	  }) : children;
	}

	function isEmpty(obj) {
	  return obj === undefined || obj === null || Object.keys(obj).length === 0;
	}
	function GlobalStyles(props) {
	  const {
	    styles,
	    defaultTheme = {}
	  } = props;
	  const globalStyles = typeof styles === 'function' ? themeInput => styles(isEmpty(themeInput) ? defaultTheme : themeInput) : styles;
	  return /*#__PURE__*/jsxRuntimeExports.jsx(Global, {
	    styles: globalStyles
	  });
	}

	/**
	 * @mui/styled-engine v5.15.14
	 *
	 * @license MIT
	 * This source code is licensed under the MIT license found in the
	 * LICENSE file in the root directory of this source tree.
	 */
	function styled$2(tag, options) {
	  const stylesFactory = newStyled(tag, options);
	  return stylesFactory;
	}

	// eslint-disable-next-line @typescript-eslint/naming-convention
	const internal_processStyles = (tag, processor) => {
	  // Emotion attaches all the styles as `__emotion_styles`.
	  // Ref: https://github.com/emotion-js/emotion/blob/16d971d0da229596d6bcc39d282ba9753c9ee7cf/packages/styled/src/base.js#L186
	  if (Array.isArray(tag.__emotion_styles)) {
	    tag.__emotion_styles = processor(tag.__emotion_styles);
	  }
	};

	var styledEngine = /*#__PURE__*/Object.freeze({
		__proto__: null,
		GlobalStyles: GlobalStyles,
		StyledEngineProvider: StyledEngineProvider,
		ThemeContext: ThemeContext$2,
		css: css,
		default: styled$2,
		internal_processStyles: internal_processStyles,
		keyframes: keyframes
	});

	// https://github.com/sindresorhus/is-plain-obj/blob/main/index.js
	function isPlainObject(item) {
	  if (typeof item !== 'object' || item === null) {
	    return false;
	  }
	  const prototype = Object.getPrototypeOf(item);
	  return (prototype === null || prototype === Object.prototype || Object.getPrototypeOf(prototype) === null) && !(Symbol.toStringTag in item) && !(Symbol.iterator in item);
	}
	function deepClone(source) {
	  if (!isPlainObject(source)) {
	    return source;
	  }
	  const output = {};
	  Object.keys(source).forEach(key => {
	    output[key] = deepClone(source[key]);
	  });
	  return output;
	}
	function deepmerge$1(target, source, options = {
	  clone: true
	}) {
	  const output = options.clone ? _extends$1({}, target) : target;
	  if (isPlainObject(target) && isPlainObject(source)) {
	    Object.keys(source).forEach(key => {
	      if (isPlainObject(source[key]) &&
	      // Avoid prototype pollution
	      Object.prototype.hasOwnProperty.call(target, key) && isPlainObject(target[key])) {
	        // Since `output` is a clone of `target` and we have narrowed `target` in this block we can cast to the same type.
	        output[key] = deepmerge$1(target[key], source[key], options);
	      } else if (options.clone) {
	        output[key] = isPlainObject(source[key]) ? deepClone(source[key]) : source[key];
	      } else {
	        output[key] = source[key];
	      }
	    });
	  }
	  return output;
	}

	var deepmerge = /*#__PURE__*/Object.freeze({
		__proto__: null,
		default: deepmerge$1,
		isPlainObject: isPlainObject
	});

	const _excluded$w = ["values", "unit", "step"];
	const sortBreakpointsValues = values => {
	  const breakpointsAsArray = Object.keys(values).map(key => ({
	    key,
	    val: values[key]
	  })) || [];
	  // Sort in ascending order
	  breakpointsAsArray.sort((breakpoint1, breakpoint2) => breakpoint1.val - breakpoint2.val);
	  return breakpointsAsArray.reduce((acc, obj) => {
	    return _extends$1({}, acc, {
	      [obj.key]: obj.val
	    });
	  }, {});
	};

	// Keep in mind that @media is inclusive by the CSS specification.
	function createBreakpoints(breakpoints) {
	  const {
	      // The breakpoint **start** at this value.
	      // For instance with the first breakpoint xs: [xs, sm).
	      values = {
	        xs: 0,
	        // phone
	        sm: 600,
	        // tablet
	        md: 900,
	        // small laptop
	        lg: 1200,
	        // desktop
	        xl: 1536 // large screen
	      },
	      unit = 'px',
	      step = 5
	    } = breakpoints,
	    other = _objectWithoutPropertiesLoose(breakpoints, _excluded$w);
	  const sortedValues = sortBreakpointsValues(values);
	  const keys = Object.keys(sortedValues);
	  function up(key) {
	    const value = typeof values[key] === 'number' ? values[key] : key;
	    return `@media (min-width:${value}${unit})`;
	  }
	  function down(key) {
	    const value = typeof values[key] === 'number' ? values[key] : key;
	    return `@media (max-width:${value - step / 100}${unit})`;
	  }
	  function between(start, end) {
	    const endIndex = keys.indexOf(end);
	    return `@media (min-width:${typeof values[start] === 'number' ? values[start] : start}${unit}) and ` + `(max-width:${(endIndex !== -1 && typeof values[keys[endIndex]] === 'number' ? values[keys[endIndex]] : end) - step / 100}${unit})`;
	  }
	  function only(key) {
	    if (keys.indexOf(key) + 1 < keys.length) {
	      return between(key, keys[keys.indexOf(key) + 1]);
	    }
	    return up(key);
	  }
	  function not(key) {
	    // handle first and last key separately, for better readability
	    const keyIndex = keys.indexOf(key);
	    if (keyIndex === 0) {
	      return up(keys[1]);
	    }
	    if (keyIndex === keys.length - 1) {
	      return down(keys[keyIndex]);
	    }
	    return between(key, keys[keys.indexOf(key) + 1]).replace('@media', '@media not all and');
	  }
	  return _extends$1({
	    keys,
	    values: sortedValues,
	    up,
	    down,
	    between,
	    only,
	    not,
	    unit
	  }, other);
	}

	const shape = {
	  borderRadius: 4
	};
	var shape$1 = shape;

	function merge(acc, item) {
	  if (!item) {
	    return acc;
	  }
	  return deepmerge$1(acc, item, {
	    clone: false // No need to clone deep, it's way faster.
	  });
	}

	// The breakpoint **start** at this value.
	// For instance with the first breakpoint xs: [xs, sm[.
	const values$1 = {
	  xs: 0,
	  // phone
	  sm: 600,
	  // tablet
	  md: 900,
	  // small laptop
	  lg: 1200,
	  // desktop
	  xl: 1536 // large screen
	};
	const defaultBreakpoints = {
	  // Sorted ASC by size. That's important.
	  // It can't be configured as it's used statically for propTypes.
	  keys: ['xs', 'sm', 'md', 'lg', 'xl'],
	  up: key => `@media (min-width:${values$1[key]}px)`
	};
	function handleBreakpoints(props, propValue, styleFromPropValue) {
	  const theme = props.theme || {};
	  if (Array.isArray(propValue)) {
	    const themeBreakpoints = theme.breakpoints || defaultBreakpoints;
	    return propValue.reduce((acc, item, index) => {
	      acc[themeBreakpoints.up(themeBreakpoints.keys[index])] = styleFromPropValue(propValue[index]);
	      return acc;
	    }, {});
	  }
	  if (typeof propValue === 'object') {
	    const themeBreakpoints = theme.breakpoints || defaultBreakpoints;
	    return Object.keys(propValue).reduce((acc, breakpoint) => {
	      // key is breakpoint
	      if (Object.keys(themeBreakpoints.values || values$1).indexOf(breakpoint) !== -1) {
	        const mediaKey = themeBreakpoints.up(breakpoint);
	        acc[mediaKey] = styleFromPropValue(propValue[breakpoint], breakpoint);
	      } else {
	        const cssKey = breakpoint;
	        acc[cssKey] = propValue[cssKey];
	      }
	      return acc;
	    }, {});
	  }
	  const output = styleFromPropValue(propValue);
	  return output;
	}
	function createEmptyBreakpointObject(breakpointsInput = {}) {
	  var _breakpointsInput$key;
	  const breakpointsInOrder = (_breakpointsInput$key = breakpointsInput.keys) == null ? void 0 : _breakpointsInput$key.reduce((acc, key) => {
	    const breakpointStyleKey = breakpointsInput.up(key);
	    acc[breakpointStyleKey] = {};
	    return acc;
	  }, {});
	  return breakpointsInOrder || {};
	}
	function removeUnusedBreakpoints(breakpointKeys, style) {
	  return breakpointKeys.reduce((acc, key) => {
	    const breakpointOutput = acc[key];
	    const isBreakpointUnused = !breakpointOutput || Object.keys(breakpointOutput).length === 0;
	    if (isBreakpointUnused) {
	      delete acc[key];
	    }
	    return acc;
	  }, style);
	}

	// It should to be noted that this function isn't equivalent to `text-transform: capitalize`.
	//
	// A strict capitalization should uppercase the first letter of each word in the sentence.
	// We only handle the first word.
	function capitalize$2(string) {
	  if (typeof string !== 'string') {
	    throw new Error(formatMuiErrorMessage$1(7));
	  }
	  return string.charAt(0).toUpperCase() + string.slice(1);
	}

	var capitalize$1 = /*#__PURE__*/Object.freeze({
		__proto__: null,
		default: capitalize$2
	});

	function getPath$1(obj, path, checkVars = true) {
	  if (!path || typeof path !== 'string') {
	    return null;
	  }

	  // Check if CSS variables are used
	  if (obj && obj.vars && checkVars) {
	    const val = `vars.${path}`.split('.').reduce((acc, item) => acc && acc[item] ? acc[item] : null, obj);
	    if (val != null) {
	      return val;
	    }
	  }
	  return path.split('.').reduce((acc, item) => {
	    if (acc && acc[item] != null) {
	      return acc[item];
	    }
	    return null;
	  }, obj);
	}
	function getStyleValue(themeMapping, transform, propValueFinal, userValue = propValueFinal) {
	  let value;
	  if (typeof themeMapping === 'function') {
	    value = themeMapping(propValueFinal);
	  } else if (Array.isArray(themeMapping)) {
	    value = themeMapping[propValueFinal] || userValue;
	  } else {
	    value = getPath$1(themeMapping, propValueFinal) || userValue;
	  }
	  if (transform) {
	    value = transform(value, userValue, themeMapping);
	  }
	  return value;
	}
	function style$1(options) {
	  const {
	    prop,
	    cssProperty = options.prop,
	    themeKey,
	    transform
	  } = options;

	  // false positive
	  // eslint-disable-next-line react/function-component-definition
	  const fn = props => {
	    if (props[prop] == null) {
	      return null;
	    }
	    const propValue = props[prop];
	    const theme = props.theme;
	    const themeMapping = getPath$1(theme, themeKey) || {};
	    const styleFromPropValue = propValueFinal => {
	      let value = getStyleValue(themeMapping, transform, propValueFinal);
	      if (propValueFinal === value && typeof propValueFinal === 'string') {
	        // Haven't found value
	        value = getStyleValue(themeMapping, transform, `${prop}${propValueFinal === 'default' ? '' : capitalize$2(propValueFinal)}`, propValueFinal);
	      }
	      if (cssProperty === false) {
	        return value;
	      }
	      return {
	        [cssProperty]: value
	      };
	    };
	    return handleBreakpoints(props, propValue, styleFromPropValue);
	  };
	  fn.propTypes = {};
	  fn.filterProps = [prop];
	  return fn;
	}

	function memoize(fn) {
	  const cache = {};
	  return arg => {
	    if (cache[arg] === undefined) {
	      cache[arg] = fn(arg);
	    }
	    return cache[arg];
	  };
	}

	const properties = {
	  m: 'margin',
	  p: 'padding'
	};
	const directions = {
	  t: 'Top',
	  r: 'Right',
	  b: 'Bottom',
	  l: 'Left',
	  x: ['Left', 'Right'],
	  y: ['Top', 'Bottom']
	};
	const aliases = {
	  marginX: 'mx',
	  marginY: 'my',
	  paddingX: 'px',
	  paddingY: 'py'
	};

	// memoize() impact:
	// From 300,000 ops/sec
	// To 350,000 ops/sec
	const getCssProperties = memoize(prop => {
	  // It's not a shorthand notation.
	  if (prop.length > 2) {
	    if (aliases[prop]) {
	      prop = aliases[prop];
	    } else {
	      return [prop];
	    }
	  }
	  const [a, b] = prop.split('');
	  const property = properties[a];
	  const direction = directions[b] || '';
	  return Array.isArray(direction) ? direction.map(dir => property + dir) : [property + direction];
	});
	const marginKeys = ['m', 'mt', 'mr', 'mb', 'ml', 'mx', 'my', 'margin', 'marginTop', 'marginRight', 'marginBottom', 'marginLeft', 'marginX', 'marginY', 'marginInline', 'marginInlineStart', 'marginInlineEnd', 'marginBlock', 'marginBlockStart', 'marginBlockEnd'];
	const paddingKeys = ['p', 'pt', 'pr', 'pb', 'pl', 'px', 'py', 'padding', 'paddingTop', 'paddingRight', 'paddingBottom', 'paddingLeft', 'paddingX', 'paddingY', 'paddingInline', 'paddingInlineStart', 'paddingInlineEnd', 'paddingBlock', 'paddingBlockStart', 'paddingBlockEnd'];
	[...marginKeys, ...paddingKeys];
	function createUnaryUnit(theme, themeKey, defaultValue, propName) {
	  var _getPath;
	  const themeSpacing = (_getPath = getPath$1(theme, themeKey, false)) != null ? _getPath : defaultValue;
	  if (typeof themeSpacing === 'number') {
	    return abs => {
	      if (typeof abs === 'string') {
	        return abs;
	      }
	      return themeSpacing * abs;
	    };
	  }
	  if (Array.isArray(themeSpacing)) {
	    return abs => {
	      if (typeof abs === 'string') {
	        return abs;
	      }
	      return themeSpacing[abs];
	    };
	  }
	  if (typeof themeSpacing === 'function') {
	    return themeSpacing;
	  }
	  return () => undefined;
	}
	function createUnarySpacing(theme) {
	  return createUnaryUnit(theme, 'spacing', 8);
	}
	function getValue(transformer, propValue) {
	  if (typeof propValue === 'string' || propValue == null) {
	    return propValue;
	  }
	  const abs = Math.abs(propValue);
	  const transformed = transformer(abs);
	  if (propValue >= 0) {
	    return transformed;
	  }
	  if (typeof transformed === 'number') {
	    return -transformed;
	  }
	  return `-${transformed}`;
	}
	function getStyleFromPropValue(cssProperties, transformer) {
	  return propValue => cssProperties.reduce((acc, cssProperty) => {
	    acc[cssProperty] = getValue(transformer, propValue);
	    return acc;
	  }, {});
	}
	function resolveCssProperty(props, keys, prop, transformer) {
	  // Using a hash computation over an array iteration could be faster, but with only 28 items,
	  // it's doesn't worth the bundle size.
	  if (keys.indexOf(prop) === -1) {
	    return null;
	  }
	  const cssProperties = getCssProperties(prop);
	  const styleFromPropValue = getStyleFromPropValue(cssProperties, transformer);
	  const propValue = props[prop];
	  return handleBreakpoints(props, propValue, styleFromPropValue);
	}
	function style(props, keys) {
	  const transformer = createUnarySpacing(props.theme);
	  return Object.keys(props).map(prop => resolveCssProperty(props, keys, prop, transformer)).reduce(merge, {});
	}
	function margin(props) {
	  return style(props, marginKeys);
	}
	margin.propTypes = {};
	margin.filterProps = marginKeys;
	function padding(props) {
	  return style(props, paddingKeys);
	}
	padding.propTypes = {};
	padding.filterProps = paddingKeys;

	// The different signatures imply different meaning for their arguments that can't be expressed structurally.
	// We express the difference with variable names.

	function createSpacing(spacingInput = 8) {
	  // Already transformed.
	  if (spacingInput.mui) {
	    return spacingInput;
	  }

	  // Material Design layouts are visually balanced. Most measurements align to an 8dp grid, which aligns both spacing and the overall layout.
	  // Smaller components, such as icons, can align to a 4dp grid.
	  // https://m2.material.io/design/layout/understanding-layout.html
	  const transform = createUnarySpacing({
	    spacing: spacingInput
	  });
	  const spacing = (...argsInput) => {
	    const args = argsInput.length === 0 ? [1] : argsInput;
	    return args.map(argument => {
	      const output = transform(argument);
	      return typeof output === 'number' ? `${output}px` : output;
	    }).join(' ');
	  };
	  spacing.mui = true;
	  return spacing;
	}

	function compose(...styles) {
	  const handlers = styles.reduce((acc, style) => {
	    style.filterProps.forEach(prop => {
	      acc[prop] = style;
	    });
	    return acc;
	  }, {});

	  // false positive
	  // eslint-disable-next-line react/function-component-definition
	  const fn = props => {
	    return Object.keys(props).reduce((acc, prop) => {
	      if (handlers[prop]) {
	        return merge(acc, handlers[prop](props));
	      }
	      return acc;
	    }, {});
	  };
	  fn.propTypes = {};
	  fn.filterProps = styles.reduce((acc, style) => acc.concat(style.filterProps), []);
	  return fn;
	}

	function borderTransform(value) {
	  if (typeof value !== 'number') {
	    return value;
	  }
	  return `${value}px solid`;
	}
	function createBorderStyle(prop, transform) {
	  return style$1({
	    prop,
	    themeKey: 'borders',
	    transform
	  });
	}
	const border = createBorderStyle('border', borderTransform);
	const borderTop = createBorderStyle('borderTop', borderTransform);
	const borderRight = createBorderStyle('borderRight', borderTransform);
	const borderBottom = createBorderStyle('borderBottom', borderTransform);
	const borderLeft = createBorderStyle('borderLeft', borderTransform);
	const borderColor = createBorderStyle('borderColor');
	const borderTopColor = createBorderStyle('borderTopColor');
	const borderRightColor = createBorderStyle('borderRightColor');
	const borderBottomColor = createBorderStyle('borderBottomColor');
	const borderLeftColor = createBorderStyle('borderLeftColor');
	const outline = createBorderStyle('outline', borderTransform);
	const outlineColor = createBorderStyle('outlineColor');

	// false positive
	// eslint-disable-next-line react/function-component-definition
	const borderRadius = props => {
	  if (props.borderRadius !== undefined && props.borderRadius !== null) {
	    const transformer = createUnaryUnit(props.theme, 'shape.borderRadius', 4);
	    const styleFromPropValue = propValue => ({
	      borderRadius: getValue(transformer, propValue)
	    });
	    return handleBreakpoints(props, props.borderRadius, styleFromPropValue);
	  }
	  return null;
	};
	borderRadius.propTypes = {};
	borderRadius.filterProps = ['borderRadius'];
	compose(border, borderTop, borderRight, borderBottom, borderLeft, borderColor, borderTopColor, borderRightColor, borderBottomColor, borderLeftColor, borderRadius, outline, outlineColor);

	// false positive
	// eslint-disable-next-line react/function-component-definition
	const gap = props => {
	  if (props.gap !== undefined && props.gap !== null) {
	    const transformer = createUnaryUnit(props.theme, 'spacing', 8);
	    const styleFromPropValue = propValue => ({
	      gap: getValue(transformer, propValue)
	    });
	    return handleBreakpoints(props, props.gap, styleFromPropValue);
	  }
	  return null;
	};
	gap.propTypes = {};
	gap.filterProps = ['gap'];

	// false positive
	// eslint-disable-next-line react/function-component-definition
	const columnGap = props => {
	  if (props.columnGap !== undefined && props.columnGap !== null) {
	    const transformer = createUnaryUnit(props.theme, 'spacing', 8);
	    const styleFromPropValue = propValue => ({
	      columnGap: getValue(transformer, propValue)
	    });
	    return handleBreakpoints(props, props.columnGap, styleFromPropValue);
	  }
	  return null;
	};
	columnGap.propTypes = {};
	columnGap.filterProps = ['columnGap'];

	// false positive
	// eslint-disable-next-line react/function-component-definition
	const rowGap = props => {
	  if (props.rowGap !== undefined && props.rowGap !== null) {
	    const transformer = createUnaryUnit(props.theme, 'spacing', 8);
	    const styleFromPropValue = propValue => ({
	      rowGap: getValue(transformer, propValue)
	    });
	    return handleBreakpoints(props, props.rowGap, styleFromPropValue);
	  }
	  return null;
	};
	rowGap.propTypes = {};
	rowGap.filterProps = ['rowGap'];
	const gridColumn = style$1({
	  prop: 'gridColumn'
	});
	const gridRow = style$1({
	  prop: 'gridRow'
	});
	const gridAutoFlow = style$1({
	  prop: 'gridAutoFlow'
	});
	const gridAutoColumns = style$1({
	  prop: 'gridAutoColumns'
	});
	const gridAutoRows = style$1({
	  prop: 'gridAutoRows'
	});
	const gridTemplateColumns = style$1({
	  prop: 'gridTemplateColumns'
	});
	const gridTemplateRows = style$1({
	  prop: 'gridTemplateRows'
	});
	const gridTemplateAreas = style$1({
	  prop: 'gridTemplateAreas'
	});
	const gridArea = style$1({
	  prop: 'gridArea'
	});
	compose(gap, columnGap, rowGap, gridColumn, gridRow, gridAutoFlow, gridAutoColumns, gridAutoRows, gridTemplateColumns, gridTemplateRows, gridTemplateAreas, gridArea);

	function paletteTransform(value, userValue) {
	  if (userValue === 'grey') {
	    return userValue;
	  }
	  return value;
	}
	const color = style$1({
	  prop: 'color',
	  themeKey: 'palette',
	  transform: paletteTransform
	});
	const bgcolor = style$1({
	  prop: 'bgcolor',
	  cssProperty: 'backgroundColor',
	  themeKey: 'palette',
	  transform: paletteTransform
	});
	const backgroundColor = style$1({
	  prop: 'backgroundColor',
	  themeKey: 'palette',
	  transform: paletteTransform
	});
	compose(color, bgcolor, backgroundColor);

	function sizingTransform(value) {
	  return value <= 1 && value !== 0 ? `${value * 100}%` : value;
	}
	const width = style$1({
	  prop: 'width',
	  transform: sizingTransform
	});
	const maxWidth = props => {
	  if (props.maxWidth !== undefined && props.maxWidth !== null) {
	    const styleFromPropValue = propValue => {
	      var _props$theme, _props$theme2;
	      const breakpoint = ((_props$theme = props.theme) == null || (_props$theme = _props$theme.breakpoints) == null || (_props$theme = _props$theme.values) == null ? void 0 : _props$theme[propValue]) || values$1[propValue];
	      if (!breakpoint) {
	        return {
	          maxWidth: sizingTransform(propValue)
	        };
	      }
	      if (((_props$theme2 = props.theme) == null || (_props$theme2 = _props$theme2.breakpoints) == null ? void 0 : _props$theme2.unit) !== 'px') {
	        return {
	          maxWidth: `${breakpoint}${props.theme.breakpoints.unit}`
	        };
	      }
	      return {
	        maxWidth: breakpoint
	      };
	    };
	    return handleBreakpoints(props, props.maxWidth, styleFromPropValue);
	  }
	  return null;
	};
	maxWidth.filterProps = ['maxWidth'];
	const minWidth = style$1({
	  prop: 'minWidth',
	  transform: sizingTransform
	});
	const height = style$1({
	  prop: 'height',
	  transform: sizingTransform
	});
	const maxHeight = style$1({
	  prop: 'maxHeight',
	  transform: sizingTransform
	});
	const minHeight = style$1({
	  prop: 'minHeight',
	  transform: sizingTransform
	});
	style$1({
	  prop: 'size',
	  cssProperty: 'width',
	  transform: sizingTransform
	});
	style$1({
	  prop: 'size',
	  cssProperty: 'height',
	  transform: sizingTransform
	});
	const boxSizing = style$1({
	  prop: 'boxSizing'
	});
	compose(width, maxWidth, minWidth, height, maxHeight, minHeight, boxSizing);

	const defaultSxConfig = {
	  // borders
	  border: {
	    themeKey: 'borders',
	    transform: borderTransform
	  },
	  borderTop: {
	    themeKey: 'borders',
	    transform: borderTransform
	  },
	  borderRight: {
	    themeKey: 'borders',
	    transform: borderTransform
	  },
	  borderBottom: {
	    themeKey: 'borders',
	    transform: borderTransform
	  },
	  borderLeft: {
	    themeKey: 'borders',
	    transform: borderTransform
	  },
	  borderColor: {
	    themeKey: 'palette'
	  },
	  borderTopColor: {
	    themeKey: 'palette'
	  },
	  borderRightColor: {
	    themeKey: 'palette'
	  },
	  borderBottomColor: {
	    themeKey: 'palette'
	  },
	  borderLeftColor: {
	    themeKey: 'palette'
	  },
	  outline: {
	    themeKey: 'borders',
	    transform: borderTransform
	  },
	  outlineColor: {
	    themeKey: 'palette'
	  },
	  borderRadius: {
	    themeKey: 'shape.borderRadius',
	    style: borderRadius
	  },
	  // palette
	  color: {
	    themeKey: 'palette',
	    transform: paletteTransform
	  },
	  bgcolor: {
	    themeKey: 'palette',
	    cssProperty: 'backgroundColor',
	    transform: paletteTransform
	  },
	  backgroundColor: {
	    themeKey: 'palette',
	    transform: paletteTransform
	  },
	  // spacing
	  p: {
	    style: padding
	  },
	  pt: {
	    style: padding
	  },
	  pr: {
	    style: padding
	  },
	  pb: {
	    style: padding
	  },
	  pl: {
	    style: padding
	  },
	  px: {
	    style: padding
	  },
	  py: {
	    style: padding
	  },
	  padding: {
	    style: padding
	  },
	  paddingTop: {
	    style: padding
	  },
	  paddingRight: {
	    style: padding
	  },
	  paddingBottom: {
	    style: padding
	  },
	  paddingLeft: {
	    style: padding
	  },
	  paddingX: {
	    style: padding
	  },
	  paddingY: {
	    style: padding
	  },
	  paddingInline: {
	    style: padding
	  },
	  paddingInlineStart: {
	    style: padding
	  },
	  paddingInlineEnd: {
	    style: padding
	  },
	  paddingBlock: {
	    style: padding
	  },
	  paddingBlockStart: {
	    style: padding
	  },
	  paddingBlockEnd: {
	    style: padding
	  },
	  m: {
	    style: margin
	  },
	  mt: {
	    style: margin
	  },
	  mr: {
	    style: margin
	  },
	  mb: {
	    style: margin
	  },
	  ml: {
	    style: margin
	  },
	  mx: {
	    style: margin
	  },
	  my: {
	    style: margin
	  },
	  margin: {
	    style: margin
	  },
	  marginTop: {
	    style: margin
	  },
	  marginRight: {
	    style: margin
	  },
	  marginBottom: {
	    style: margin
	  },
	  marginLeft: {
	    style: margin
	  },
	  marginX: {
	    style: margin
	  },
	  marginY: {
	    style: margin
	  },
	  marginInline: {
	    style: margin
	  },
	  marginInlineStart: {
	    style: margin
	  },
	  marginInlineEnd: {
	    style: margin
	  },
	  marginBlock: {
	    style: margin
	  },
	  marginBlockStart: {
	    style: margin
	  },
	  marginBlockEnd: {
	    style: margin
	  },
	  // display
	  displayPrint: {
	    cssProperty: false,
	    transform: value => ({
	      '@media print': {
	        display: value
	      }
	    })
	  },
	  display: {},
	  overflow: {},
	  textOverflow: {},
	  visibility: {},
	  whiteSpace: {},
	  // flexbox
	  flexBasis: {},
	  flexDirection: {},
	  flexWrap: {},
	  justifyContent: {},
	  alignItems: {},
	  alignContent: {},
	  order: {},
	  flex: {},
	  flexGrow: {},
	  flexShrink: {},
	  alignSelf: {},
	  justifyItems: {},
	  justifySelf: {},
	  // grid
	  gap: {
	    style: gap
	  },
	  rowGap: {
	    style: rowGap
	  },
	  columnGap: {
	    style: columnGap
	  },
	  gridColumn: {},
	  gridRow: {},
	  gridAutoFlow: {},
	  gridAutoColumns: {},
	  gridAutoRows: {},
	  gridTemplateColumns: {},
	  gridTemplateRows: {},
	  gridTemplateAreas: {},
	  gridArea: {},
	  // positions
	  position: {},
	  zIndex: {
	    themeKey: 'zIndex'
	  },
	  top: {},
	  right: {},
	  bottom: {},
	  left: {},
	  // shadows
	  boxShadow: {
	    themeKey: 'shadows'
	  },
	  // sizing
	  width: {
	    transform: sizingTransform
	  },
	  maxWidth: {
	    style: maxWidth
	  },
	  minWidth: {
	    transform: sizingTransform
	  },
	  height: {
	    transform: sizingTransform
	  },
	  maxHeight: {
	    transform: sizingTransform
	  },
	  minHeight: {
	    transform: sizingTransform
	  },
	  boxSizing: {},
	  // typography
	  fontFamily: {
	    themeKey: 'typography'
	  },
	  fontSize: {
	    themeKey: 'typography'
	  },
	  fontStyle: {
	    themeKey: 'typography'
	  },
	  fontWeight: {
	    themeKey: 'typography'
	  },
	  letterSpacing: {},
	  textTransform: {},
	  lineHeight: {},
	  textAlign: {},
	  typography: {
	    cssProperty: false,
	    themeKey: 'typography'
	  }
	};
	var defaultSxConfig$1 = defaultSxConfig;

	function objectsHaveSameKeys(...objects) {
	  const allKeys = objects.reduce((keys, object) => keys.concat(Object.keys(object)), []);
	  const union = new Set(allKeys);
	  return objects.every(object => union.size === Object.keys(object).length);
	}
	function callIfFn(maybeFn, arg) {
	  return typeof maybeFn === 'function' ? maybeFn(arg) : maybeFn;
	}

	// eslint-disable-next-line @typescript-eslint/naming-convention
	function unstable_createStyleFunctionSx() {
	  function getThemeValue(prop, val, theme, config) {
	    const props = {
	      [prop]: val,
	      theme
	    };
	    const options = config[prop];
	    if (!options) {
	      return {
	        [prop]: val
	      };
	    }
	    const {
	      cssProperty = prop,
	      themeKey,
	      transform,
	      style
	    } = options;
	    if (val == null) {
	      return null;
	    }

	    // TODO v6: remove, see https://github.com/mui/material-ui/pull/38123
	    if (themeKey === 'typography' && val === 'inherit') {
	      return {
	        [prop]: val
	      };
	    }
	    const themeMapping = getPath$1(theme, themeKey) || {};
	    if (style) {
	      return style(props);
	    }
	    const styleFromPropValue = propValueFinal => {
	      let value = getStyleValue(themeMapping, transform, propValueFinal);
	      if (propValueFinal === value && typeof propValueFinal === 'string') {
	        // Haven't found value
	        value = getStyleValue(themeMapping, transform, `${prop}${propValueFinal === 'default' ? '' : capitalize$2(propValueFinal)}`, propValueFinal);
	      }
	      if (cssProperty === false) {
	        return value;
	      }
	      return {
	        [cssProperty]: value
	      };
	    };
	    return handleBreakpoints(props, val, styleFromPropValue);
	  }
	  function styleFunctionSx(props) {
	    var _theme$unstable_sxCon;
	    const {
	      sx,
	      theme = {}
	    } = props || {};
	    if (!sx) {
	      return null; // Emotion & styled-components will neglect null
	    }
	    const config = (_theme$unstable_sxCon = theme.unstable_sxConfig) != null ? _theme$unstable_sxCon : defaultSxConfig$1;

	    /*
	     * Receive `sxInput` as object or callback
	     * and then recursively check keys & values to create media query object styles.
	     * (the result will be used in `styled`)
	     */
	    function traverse(sxInput) {
	      let sxObject = sxInput;
	      if (typeof sxInput === 'function') {
	        sxObject = sxInput(theme);
	      } else if (typeof sxInput !== 'object') {
	        // value
	        return sxInput;
	      }
	      if (!sxObject) {
	        return null;
	      }
	      const emptyBreakpoints = createEmptyBreakpointObject(theme.breakpoints);
	      const breakpointsKeys = Object.keys(emptyBreakpoints);
	      let css = emptyBreakpoints;
	      Object.keys(sxObject).forEach(styleKey => {
	        const value = callIfFn(sxObject[styleKey], theme);
	        if (value !== null && value !== undefined) {
	          if (typeof value === 'object') {
	            if (config[styleKey]) {
	              css = merge(css, getThemeValue(styleKey, value, theme, config));
	            } else {
	              const breakpointsValues = handleBreakpoints({
	                theme
	              }, value, x => ({
	                [styleKey]: x
	              }));
	              if (objectsHaveSameKeys(breakpointsValues, value)) {
	                css[styleKey] = styleFunctionSx({
	                  sx: value,
	                  theme
	                });
	              } else {
	                css = merge(css, breakpointsValues);
	              }
	            }
	          } else {
	            css = merge(css, getThemeValue(styleKey, value, theme, config));
	          }
	        }
	      });
	      return removeUnusedBreakpoints(breakpointsKeys, css);
	    }
	    return Array.isArray(sx) ? sx.map(traverse) : traverse(sx);
	  }
	  return styleFunctionSx;
	}
	const styleFunctionSx$1 = unstable_createStyleFunctionSx();
	styleFunctionSx$1.filterProps = ['sx'];
	var styleFunctionSx$2 = styleFunctionSx$1;

	/**
	 * A universal utility to style components with multiple color modes. Always use it from the theme object.
	 * It works with:
	 *  - [Basic theme](https://mui.com/material-ui/customization/dark-mode/)
	 *  - [CSS theme variables](https://mui.com/material-ui/experimental-api/css-theme-variables/overview/)
	 *  - Zero-runtime engine
	 *
	 * Tips: Use an array over object spread and place `theme.applyStyles()` last.
	 *
	 * ✅ [{ background: '#e5e5e5' }, theme.applyStyles('dark', { background: '#1c1c1c' })]
	 *
	 * 🚫 { background: '#e5e5e5', ...theme.applyStyles('dark', { background: '#1c1c1c' })}
	 *
	 * @example
	 * 1. using with `styled`:
	 * ```jsx
	 *   const Component = styled('div')(({ theme }) => [
	 *     { background: '#e5e5e5' },
	 *     theme.applyStyles('dark', {
	 *       background: '#1c1c1c',
	 *       color: '#fff',
	 *     }),
	 *   ]);
	 * ```
	 *
	 * @example
	 * 2. using with `sx` prop:
	 * ```jsx
	 *   <Box sx={theme => [
	 *     { background: '#e5e5e5' },
	 *     theme.applyStyles('dark', {
	 *        background: '#1c1c1c',
	 *        color: '#fff',
	 *      }),
	 *     ]}
	 *   />
	 * ```
	 *
	 * @example
	 * 3. theming a component:
	 * ```jsx
	 *   extendTheme({
	 *     components: {
	 *       MuiButton: {
	 *         styleOverrides: {
	 *           root: ({ theme }) => [
	 *             { background: '#e5e5e5' },
	 *             theme.applyStyles('dark', {
	 *               background: '#1c1c1c',
	 *               color: '#fff',
	 *             }),
	 *           ],
	 *         },
	 *       }
	 *     }
	 *   })
	 *```
	 */
	function applyStyles(key, styles) {
	  // @ts-expect-error this is 'any' type
	  const theme = this;
	  if (theme.vars && typeof theme.getColorSchemeSelector === 'function') {
	    // If CssVarsProvider is used as a provider,
	    // returns '* :where([data-mui-color-scheme="light|dark"]) &'
	    const selector = theme.getColorSchemeSelector(key).replace(/(\[[^\]]+\])/, '*:where($1)');
	    return {
	      [selector]: styles
	    };
	  }
	  if (theme.palette.mode === key) {
	    return styles;
	  }
	  return {};
	}

	const _excluded$v = ["breakpoints", "palette", "spacing", "shape"];
	function createTheme$2(options = {}, ...args) {
	  const {
	      breakpoints: breakpointsInput = {},
	      palette: paletteInput = {},
	      spacing: spacingInput,
	      shape: shapeInput = {}
	    } = options,
	    other = _objectWithoutPropertiesLoose(options, _excluded$v);
	  const breakpoints = createBreakpoints(breakpointsInput);
	  const spacing = createSpacing(spacingInput);
	  let muiTheme = deepmerge$1({
	    breakpoints,
	    direction: 'ltr',
	    components: {},
	    // Inject component definitions.
	    palette: _extends$1({
	      mode: 'light'
	    }, paletteInput),
	    spacing,
	    shape: _extends$1({}, shape$1, shapeInput)
	  }, other);
	  muiTheme.applyStyles = applyStyles;
	  muiTheme = args.reduce((acc, argument) => deepmerge$1(acc, argument), muiTheme);
	  muiTheme.unstable_sxConfig = _extends$1({}, defaultSxConfig$1, other == null ? void 0 : other.unstable_sxConfig);
	  muiTheme.unstable_sx = function sx(props) {
	    return styleFunctionSx$2({
	      sx: props,
	      theme: this
	    });
	  };
	  return muiTheme;
	}

	var createTheme$1 = /*#__PURE__*/Object.freeze({
		__proto__: null,
		default: createTheme$2,
		private_createBreakpoints: createBreakpoints,
		unstable_applyStyles: applyStyles
	});

	function isObjectEmpty(obj) {
	  return Object.keys(obj).length === 0;
	}
	function useTheme$3(defaultTheme = null) {
	  const contextTheme = reactExports.useContext(ThemeContext$2);
	  return !contextTheme || isObjectEmpty(contextTheme) ? defaultTheme : contextTheme;
	}

	const systemDefaultTheme = createTheme$2();
	function useTheme$2(defaultTheme = systemDefaultTheme) {
	  return useTheme$3(defaultTheme);
	}

	const _excluded$u = ["sx"];
	const splitProps = props => {
	  var _props$theme$unstable, _props$theme;
	  const result = {
	    systemProps: {},
	    otherProps: {}
	  };
	  const config = (_props$theme$unstable = props == null || (_props$theme = props.theme) == null ? void 0 : _props$theme.unstable_sxConfig) != null ? _props$theme$unstable : defaultSxConfig$1;
	  Object.keys(props).forEach(prop => {
	    if (config[prop]) {
	      result.systemProps[prop] = props[prop];
	    } else {
	      result.otherProps[prop] = props[prop];
	    }
	  });
	  return result;
	};
	function extendSxProp(props) {
	  const {
	      sx: inSx
	    } = props,
	    other = _objectWithoutPropertiesLoose(props, _excluded$u);
	  const {
	    systemProps,
	    otherProps
	  } = splitProps(other);
	  let finalSx;
	  if (Array.isArray(inSx)) {
	    finalSx = [systemProps, ...inSx];
	  } else if (typeof inSx === 'function') {
	    finalSx = (...args) => {
	      const result = inSx(...args);
	      if (!isPlainObject(result)) {
	        return systemProps;
	      }
	      return _extends$1({}, systemProps, result);
	    };
	  } else {
	    finalSx = _extends$1({}, systemProps, inSx);
	  }
	  return _extends$1({}, otherProps, {
	    sx: finalSx
	  });
	}

	var styleFunctionSx = /*#__PURE__*/Object.freeze({
		__proto__: null,
		default: styleFunctionSx$2,
		extendSxProp: extendSxProp,
		unstable_createStyleFunctionSx: unstable_createStyleFunctionSx,
		unstable_defaultSxConfig: defaultSxConfig$1
	});

	const defaultGenerator = componentName => componentName;
	const createClassNameGenerator = () => {
	  let generate = defaultGenerator;
	  return {
	    configure(generator) {
	      generate = generator;
	    },
	    generate(componentName) {
	      return generate(componentName);
	    },
	    reset() {
	      generate = defaultGenerator;
	    }
	  };
	};
	const ClassNameGenerator = createClassNameGenerator();
	var ClassNameGenerator$1 = ClassNameGenerator;

	function r$1(e) {
	  var t,
	    f,
	    n = "";
	  if ("string" == typeof e || "number" == typeof e) n += e;else if ("object" == typeof e) if (Array.isArray(e)) {
	    var o = e.length;
	    for (t = 0; t < o; t++) e[t] && (f = r$1(e[t])) && (n && (n += " "), n += f);
	  } else for (f in e) e[f] && (n && (n += " "), n += f);
	  return n;
	}
	function clsx() {
	  for (var e, t, f = 0, n = "", o = arguments.length; f < o; f++) (e = arguments[f]) && (t = r$1(e)) && (n && (n += " "), n += t);
	  return n;
	}

	const globalStateClasses = {
	  active: 'active',
	  checked: 'checked',
	  completed: 'completed',
	  disabled: 'disabled',
	  error: 'error',
	  expanded: 'expanded',
	  focused: 'focused',
	  focusVisible: 'focusVisible',
	  open: 'open',
	  readOnly: 'readOnly',
	  required: 'required',
	  selected: 'selected'
	};
	function generateUtilityClass(componentName, slot, globalStatePrefix = 'Mui') {
	  const globalStateClass = globalStateClasses[slot];
	  return globalStateClass ? `${globalStatePrefix}-${globalStateClass}` : `${ClassNameGenerator$1.generate(componentName)}-${slot}`;
	}

	function generateUtilityClasses(componentName, slots, globalStatePrefix = 'Mui') {
	  const result = {};
	  slots.forEach(slot => {
	    result[slot] = generateUtilityClass(componentName, slot, globalStatePrefix);
	  });
	  return result;
	}

	var reactIs = {exports: {}};

	var reactIs_production_min = {};

	/**
	 * @license React
	 * react-is.production.min.js
	 *
	 * Copyright (c) Facebook, Inc. and its affiliates.
	 *
	 * This source code is licensed under the MIT license found in the
	 * LICENSE file in the root directory of this source tree.
	 */

	var hasRequiredReactIs_production_min;

	function requireReactIs_production_min () {
		if (hasRequiredReactIs_production_min) return reactIs_production_min;
		hasRequiredReactIs_production_min = 1;

		var b = Symbol.for("react.element"),
		  c = Symbol.for("react.portal"),
		  d = Symbol.for("react.fragment"),
		  e = Symbol.for("react.strict_mode"),
		  f = Symbol.for("react.profiler"),
		  g = Symbol.for("react.provider"),
		  h = Symbol.for("react.context"),
		  k = Symbol.for("react.server_context"),
		  l = Symbol.for("react.forward_ref"),
		  m = Symbol.for("react.suspense"),
		  n = Symbol.for("react.suspense_list"),
		  p = Symbol.for("react.memo"),
		  q = Symbol.for("react.lazy"),
		  t = Symbol.for("react.offscreen"),
		  u;
		u = Symbol.for("react.module.reference");
		function v(a) {
		  if ("object" === typeof a && null !== a) {
		    var r = a.$$typeof;
		    switch (r) {
		      case b:
		        switch (a = a.type, a) {
		          case d:
		          case f:
		          case e:
		          case m:
		          case n:
		            return a;
		          default:
		            switch (a = a && a.$$typeof, a) {
		              case k:
		              case h:
		              case l:
		              case q:
		              case p:
		              case g:
		                return a;
		              default:
		                return r;
		            }
		        }
		      case c:
		        return r;
		    }
		  }
		}
		reactIs_production_min.ContextConsumer = h;
		reactIs_production_min.ContextProvider = g;
		reactIs_production_min.Element = b;
		reactIs_production_min.ForwardRef = l;
		reactIs_production_min.Fragment = d;
		reactIs_production_min.Lazy = q;
		reactIs_production_min.Memo = p;
		reactIs_production_min.Portal = c;
		reactIs_production_min.Profiler = f;
		reactIs_production_min.StrictMode = e;
		reactIs_production_min.Suspense = m;
		reactIs_production_min.SuspenseList = n;
		reactIs_production_min.isAsyncMode = function () {
		  return !1;
		};
		reactIs_production_min.isConcurrentMode = function () {
		  return !1;
		};
		reactIs_production_min.isContextConsumer = function (a) {
		  return v(a) === h;
		};
		reactIs_production_min.isContextProvider = function (a) {
		  return v(a) === g;
		};
		reactIs_production_min.isElement = function (a) {
		  return "object" === typeof a && null !== a && a.$$typeof === b;
		};
		reactIs_production_min.isForwardRef = function (a) {
		  return v(a) === l;
		};
		reactIs_production_min.isFragment = function (a) {
		  return v(a) === d;
		};
		reactIs_production_min.isLazy = function (a) {
		  return v(a) === q;
		};
		reactIs_production_min.isMemo = function (a) {
		  return v(a) === p;
		};
		reactIs_production_min.isPortal = function (a) {
		  return v(a) === c;
		};
		reactIs_production_min.isProfiler = function (a) {
		  return v(a) === f;
		};
		reactIs_production_min.isStrictMode = function (a) {
		  return v(a) === e;
		};
		reactIs_production_min.isSuspense = function (a) {
		  return v(a) === m;
		};
		reactIs_production_min.isSuspenseList = function (a) {
		  return v(a) === n;
		};
		reactIs_production_min.isValidElementType = function (a) {
		  return "string" === typeof a || "function" === typeof a || a === d || a === f || a === e || a === m || a === n || a === t || "object" === typeof a && null !== a && (a.$$typeof === q || a.$$typeof === p || a.$$typeof === g || a.$$typeof === h || a.$$typeof === l || a.$$typeof === u || void 0 !== a.getModuleId) ? !0 : !1;
		};
		reactIs_production_min.typeOf = v;
		return reactIs_production_min;
	}

	var hasRequiredReactIs;

	function requireReactIs () {
		if (hasRequiredReactIs) return reactIs.exports;
		hasRequiredReactIs = 1;

		{
		  reactIs.exports = requireReactIs_production_min();
		}
		return reactIs.exports;
	}

	var reactIsExports = requireReactIs();

	// Simplified polyfill for IE11 support
	// https://github.com/JamesMGreene/Function.name/blob/58b314d4a983110c3682f1228f845d39ccca1817/Function.name.js#L3
	const fnNameMatchRegex = /^\s*function(?:\s|\s*\/\*.*\*\/\s*)+([^(\s/]*)\s*/;
	function getFunctionName(fn) {
	  const match = `${fn}`.match(fnNameMatchRegex);
	  const name = match && match[1];
	  return name || '';
	}
	function getFunctionComponentName(Component, fallback = '') {
	  return Component.displayName || Component.name || getFunctionName(Component) || fallback;
	}
	function getWrappedName(outerType, innerType, wrapperName) {
	  const functionName = getFunctionComponentName(innerType);
	  return outerType.displayName || (functionName !== '' ? `${wrapperName}(${functionName})` : wrapperName);
	}

	/**
	 * cherry-pick from
	 * https://github.com/facebook/react/blob/769b1f270e1251d9dbdce0fcbd9e92e502d059b8/packages/shared/getComponentName.js
	 * originally forked from recompose/getDisplayName with added IE11 support
	 */
	function getDisplayName$1(Component) {
	  if (Component == null) {
	    return undefined;
	  }
	  if (typeof Component === 'string') {
	    return Component;
	  }
	  if (typeof Component === 'function') {
	    return getFunctionComponentName(Component, 'Component');
	  }

	  // TypeScript can't have components as objects but they exist in the form of `memo` or `Suspense`
	  if (typeof Component === 'object') {
	    switch (Component.$$typeof) {
	      case reactIsExports.ForwardRef:
	        return getWrappedName(Component, Component.render, 'ForwardRef');
	      case reactIsExports.Memo:
	        return getWrappedName(Component, Component.type, 'memo');
	      default:
	        return undefined;
	    }
	  }
	  return undefined;
	}

	var getDisplayName = /*#__PURE__*/Object.freeze({
		__proto__: null,
		default: getDisplayName$1,
		getFunctionName: getFunctionName
	});

	/**
	 * Add keys, values of `defaultProps` that does not exist in `props`
	 * @param {object} defaultProps
	 * @param {object} props
	 * @returns {object} resolved props
	 */
	function resolveProps(defaultProps, props) {
	  const output = _extends$1({}, props);
	  Object.keys(defaultProps).forEach(propName => {
	    if (propName.toString().match(/^(components|slots)$/)) {
	      output[propName] = _extends$1({}, defaultProps[propName], output[propName]);
	    } else if (propName.toString().match(/^(componentsProps|slotProps)$/)) {
	      const defaultSlotProps = defaultProps[propName] || {};
	      const slotProps = props[propName];
	      output[propName] = {};
	      if (!slotProps || !Object.keys(slotProps)) {
	        // Reduce the iteration if the slot props is empty
	        output[propName] = defaultSlotProps;
	      } else if (!defaultSlotProps || !Object.keys(defaultSlotProps)) {
	        // Reduce the iteration if the default slot props is empty
	        output[propName] = slotProps;
	      } else {
	        output[propName] = _extends$1({}, slotProps);
	        Object.keys(defaultSlotProps).forEach(slotPropName => {
	          output[propName][slotPropName] = resolveProps(defaultSlotProps[slotPropName], slotProps[slotPropName]);
	        });
	      }
	    } else if (output[propName] === undefined) {
	      output[propName] = defaultProps[propName];
	    }
	  });
	  return output;
	}

	function getThemeProps(params) {
	  const {
	    theme,
	    name,
	    props
	  } = params;
	  if (!theme || !theme.components || !theme.components[name] || !theme.components[name].defaultProps) {
	    return props;
	  }
	  return resolveProps(theme.components[name].defaultProps, props);
	}

	function useThemeProps$1({
	  props,
	  name,
	  defaultTheme,
	  themeId
	}) {
	  let theme = useTheme$2(defaultTheme);
	  if (themeId) {
	    theme = theme[themeId] || theme;
	  }
	  const mergedProps = getThemeProps({
	    theme,
	    name,
	    props
	  });
	  return mergedProps;
	}

	/**
	 * A version of `React.useLayoutEffect` that does not show a warning when server-side rendering.
	 * This is useful for effects that are only needed for client-side rendering but not for SSR.
	 *
	 * Before you use this hook, make sure to read https://gist.github.com/gaearon/e7d97cdf38a2907924ea12e4ebdf3c85
	 * and confirm it doesn't apply to your use-case.
	 */
	const useEnhancedEffect = typeof window !== 'undefined' ? reactExports.useLayoutEffect : reactExports.useEffect;
	var useEnhancedEffect$1 = useEnhancedEffect;

	function clamp$1(val, min = Number.MIN_SAFE_INTEGER, max = Number.MAX_SAFE_INTEGER) {
	  return Math.max(min, Math.min(val, max));
	}

	var clamp = /*#__PURE__*/Object.freeze({
		__proto__: null,
		default: clamp$1
	});

	/**
	 * Safe chained function.
	 *
	 * Will only create a new function if needed,
	 * otherwise will pass back existing functions or null.
	 */
	function createChainedFunction(...funcs) {
	  return funcs.reduce((acc, func) => {
	    if (func == null) {
	      return acc;
	    }
	    return function chainedFunction(...args) {
	      acc.apply(this, args);
	      func.apply(this, args);
	    };
	  }, () => {});
	}

	// Corresponds to 10 frames at 60 Hz.
	// A few bytes payload overhead when lodash/debounce is ~3 kB and debounce ~300 B.
	function debounce(func, wait = 166) {
	  let timeout;
	  function debounced(...args) {
	    const later = () => {
	      // @ts-ignore
	      func.apply(this, args);
	    };
	    clearTimeout(timeout);
	    timeout = setTimeout(later, wait);
	  }
	  debounced.clear = () => {
	    clearTimeout(timeout);
	  };
	  return debounced;
	}

	function deprecatedPropType(validator, reason) {
	  {
	    return () => null;
	  }
	}

	function isMuiElement(element, muiNames) {
	  var _muiName, _element$type;
	  return /*#__PURE__*/ /*#__PURE__*/reactExports.isValidElement(element) && muiNames.indexOf(
	  // For server components `muiName` is avaialble in element.type._payload.value.muiName
	  // relevant info - https://github.com/facebook/react/blob/2807d781a08db8e9873687fccc25c0f12b4fb3d4/packages/react/src/ReactLazy.js#L45
	  // eslint-disable-next-line no-underscore-dangle
	  (_muiName = element.type.muiName) != null ? _muiName : (_element$type = element.type) == null || (_element$type = _element$type._payload) == null || (_element$type = _element$type.value) == null ? void 0 : _element$type.muiName) !== -1;
	}

	function ownerDocument(node) {
	  return node && node.ownerDocument || document;
	}

	function ownerWindow(node) {
	  const doc = ownerDocument(node);
	  return doc.defaultView || window;
	}

	function requirePropFactory(componentNameInError, Component) {
	  {
	    return () => null;
	  }
	}

	/**
	 * TODO v5: consider making it private
	 *
	 * passes {value} to {ref}
	 *
	 * WARNING: Be sure to only call this inside a callback that is passed as a ref.
	 * Otherwise, make sure to cleanup the previous {ref} if it changes. See
	 * https://github.com/mui/material-ui/issues/13539
	 *
	 * Useful if you want to expose the ref of an inner component to the public API
	 * while still using it inside the component.
	 * @param ref A ref callback or ref object. If anything falsy, this is a no-op.
	 */
	function setRef(ref, value) {
	  if (typeof ref === 'function') {
	    ref(value);
	  } else if (ref) {
	    ref.current = value;
	  }
	}

	let globalId = 0;
	function useGlobalId(idOverride) {
	  const [defaultId, setDefaultId] = reactExports.useState(idOverride);
	  const id = idOverride || defaultId;
	  reactExports.useEffect(() => {
	    if (defaultId == null) {
	      // Fallback to this default id when possible.
	      // Use the incrementing value for client-side rendering only.
	      // We can't use it server-side.
	      // If you want to use random values please consider the Birthday Problem: https://en.wikipedia.org/wiki/Birthday_problem
	      globalId += 1;
	      setDefaultId(`mui-${globalId}`);
	    }
	  }, [defaultId]);
	  return id;
	}

	// downstream bundlers may remove unnecessary concatenation, but won't remove toString call -- Workaround for https://github.com/webpack/webpack/issues/14814
	const maybeReactUseId = React$1['useId'.toString()];
	/**
	 *
	 * @example <div id={useId()} />
	 * @param idOverride
	 * @returns {string}
	 */
	function useId(idOverride) {
	  if (maybeReactUseId !== undefined) {
	    const reactId = maybeReactUseId();
	    return idOverride != null ? idOverride : reactId;
	  }
	  // eslint-disable-next-line react-hooks/rules-of-hooks -- `React.useId` is invariant at runtime.
	  return useGlobalId(idOverride);
	}

	function unsupportedProp(props, propName, componentName, location, propFullName) {
	  {
	    return null;
	  }
	}

	function useControlled({
	  controlled,
	  default: defaultProp,
	  name,
	  state = 'value'
	}) {
	  // isControlled is ignored in the hook dependency lists as it should never change.
	  const {
	    current: isControlled
	  } = reactExports.useRef(controlled !== undefined);
	  const [valueState, setValue] = reactExports.useState(defaultProp);
	  const value = isControlled ? controlled : valueState;
	  const setValueIfUncontrolled = reactExports.useCallback(newValue => {
	    if (!isControlled) {
	      setValue(newValue);
	    }
	  }, []);
	  return [value, setValueIfUncontrolled];
	}

	/**
	 * Inspired by https://github.com/facebook/react/issues/14099#issuecomment-440013892
	 * See RFC in https://github.com/reactjs/rfcs/pull/220
	 */

	function useEventCallback(fn) {
	  const ref = reactExports.useRef(fn);
	  useEnhancedEffect$1(() => {
	    ref.current = fn;
	  });
	  return reactExports.useRef((...args) =>
	  // @ts-expect-error hide `this`
	  (0, ref.current)(...args)).current;
	}

	function useForkRef(...refs) {
	  /**
	   * This will create a new function if the refs passed to this hook change and are all defined.
	   * This means react will call the old forkRef with `null` and the new forkRef
	   * with the ref. Cleanup naturally emerges from this behavior.
	   */
	  return reactExports.useMemo(() => {
	    if (refs.every(ref => ref == null)) {
	      return null;
	    }
	    return instance => {
	      refs.forEach(ref => {
	        setRef(ref, instance);
	      });
	    };
	    // eslint-disable-next-line react-hooks/exhaustive-deps
	  }, refs);
	}

	const UNINITIALIZED = {};

	/**
	 * A React.useRef() that is initialized lazily with a function. Note that it accepts an optional
	 * initialization argument, so the initialization function doesn't need to be an inline closure.
	 *
	 * @usage
	 *   const ref = useLazyRef(sortColumns, columns)
	 */
	function useLazyRef(init, initArg) {
	  const ref = reactExports.useRef(UNINITIALIZED);
	  if (ref.current === UNINITIALIZED) {
	    ref.current = init(initArg);
	  }
	  return ref;
	}

	const EMPTY = [];

	/**
	 * A React.useEffect equivalent that runs once, when the component is mounted.
	 */
	function useOnMount(fn) {
	  /* eslint-disable react-hooks/exhaustive-deps */
	  reactExports.useEffect(fn, EMPTY);
	  /* eslint-enable react-hooks/exhaustive-deps */
	}

	class Timeout {
	  constructor() {
	    this.currentId = null;
	    this.clear = () => {
	      if (this.currentId !== null) {
	        clearTimeout(this.currentId);
	        this.currentId = null;
	      }
	    };
	    this.disposeEffect = () => {
	      return this.clear;
	    };
	  }
	  static create() {
	    return new Timeout();
	  }
	  /**
	   * Executes `fn` after `delay`, clearing any previously scheduled call.
	   */
	  start(delay, fn) {
	    this.clear();
	    this.currentId = setTimeout(() => {
	      this.currentId = null;
	      fn();
	    }, delay);
	  }
	}
	function useTimeout() {
	  const timeout = useLazyRef(Timeout.create).current;
	  useOnMount(timeout.disposeEffect);
	  return timeout;
	}

	let hadKeyboardEvent = true;
	let hadFocusVisibleRecently = false;
	const hadFocusVisibleRecentlyTimeout = new Timeout();
	const inputTypesWhitelist = {
	  text: true,
	  search: true,
	  url: true,
	  tel: true,
	  email: true,
	  password: true,
	  number: true,
	  date: true,
	  month: true,
	  week: true,
	  time: true,
	  datetime: true,
	  'datetime-local': true
	};

	/**
	 * Computes whether the given element should automatically trigger the
	 * `focus-visible` class being added, i.e. whether it should always match
	 * `:focus-visible` when focused.
	 * @param {Element} node
	 * @returns {boolean}
	 */
	function focusTriggersKeyboardModality(node) {
	  const {
	    type,
	    tagName
	  } = node;
	  if (tagName === 'INPUT' && inputTypesWhitelist[type] && !node.readOnly) {
	    return true;
	  }
	  if (tagName === 'TEXTAREA' && !node.readOnly) {
	    return true;
	  }
	  if (node.isContentEditable) {
	    return true;
	  }
	  return false;
	}

	/**
	 * Keep track of our keyboard modality state with `hadKeyboardEvent`.
	 * If the most recent user interaction was via the keyboard;
	 * and the key press did not include a meta, alt/option, or control key;
	 * then the modality is keyboard. Otherwise, the modality is not keyboard.
	 * @param {KeyboardEvent} event
	 */
	function handleKeyDown(event) {
	  if (event.metaKey || event.altKey || event.ctrlKey) {
	    return;
	  }
	  hadKeyboardEvent = true;
	}

	/**
	 * If at any point a user clicks with a pointing device, ensure that we change
	 * the modality away from keyboard.
	 * This avoids the situation where a user presses a key on an already focused
	 * element, and then clicks on a different element, focusing it with a
	 * pointing device, while we still think we're in keyboard modality.
	 */
	function handlePointerDown() {
	  hadKeyboardEvent = false;
	}
	function handleVisibilityChange() {
	  if (this.visibilityState === 'hidden') {
	    // If the tab becomes active again, the browser will handle calling focus
	    // on the element (Safari actually calls it twice).
	    // If this tab change caused a blur on an element with focus-visible,
	    // re-apply the class when the user switches back to the tab.
	    if (hadFocusVisibleRecently) {
	      hadKeyboardEvent = true;
	    }
	  }
	}
	function prepare(doc) {
	  doc.addEventListener('keydown', handleKeyDown, true);
	  doc.addEventListener('mousedown', handlePointerDown, true);
	  doc.addEventListener('pointerdown', handlePointerDown, true);
	  doc.addEventListener('touchstart', handlePointerDown, true);
	  doc.addEventListener('visibilitychange', handleVisibilityChange, true);
	}
	function isFocusVisible(event) {
	  const {
	    target
	  } = event;
	  try {
	    return target.matches(':focus-visible');
	  } catch (error) {
	    // Browsers not implementing :focus-visible will throw a SyntaxError.
	    // We use our own heuristic for those browsers.
	    // Rethrow might be better if it's not the expected error but do we really
	    // want to crash if focus-visible malfunctioned?
	  }

	  // No need for validFocusTarget check. The user does that by attaching it to
	  // focusable events only.
	  return hadKeyboardEvent || focusTriggersKeyboardModality(target);
	}
	function useIsFocusVisible() {
	  const ref = reactExports.useCallback(node => {
	    if (node != null) {
	      prepare(node.ownerDocument);
	    }
	  }, []);
	  const isFocusVisibleRef = reactExports.useRef(false);

	  /**
	   * Should be called if a blur event is fired
	   */
	  function handleBlurVisible() {
	    // checking against potential state variable does not suffice if we focus and blur synchronously.
	    // React wouldn't have time to trigger a re-render so `focusVisible` would be stale.
	    // Ideally we would adjust `isFocusVisible(event)` to look at `relatedTarget` for blur events.
	    // This doesn't work in IE11 due to https://github.com/facebook/react/issues/3751
	    // TODO: check again if React releases their internal changes to focus event handling (https://github.com/facebook/react/pull/19186).
	    if (isFocusVisibleRef.current) {
	      // To detect a tab/window switch, we look for a blur event followed
	      // rapidly by a visibility change.
	      // If we don't see a visibility change within 100ms, it's probably a
	      // regular focus change.
	      hadFocusVisibleRecently = true;
	      hadFocusVisibleRecentlyTimeout.start(100, () => {
	        hadFocusVisibleRecently = false;
	      });
	      isFocusVisibleRef.current = false;
	      return true;
	    }
	    return false;
	  }

	  /**
	   * Should be called if a blur event is fired
	   */
	  function handleFocusVisible(event) {
	    if (isFocusVisible(event)) {
	      isFocusVisibleRef.current = true;
	      return true;
	    }
	    return false;
	  }
	  return {
	    isFocusVisibleRef,
	    onFocus: handleFocusVisible,
	    onBlur: handleBlurVisible,
	    ref
	  };
	}

	// A change of the browser zoom change the scrollbar size.
	// Credit https://github.com/twbs/bootstrap/blob/488fd8afc535ca3a6ad4dc581f5e89217b6a36ac/js/src/util/scrollbar.js#L14-L18
	function getScrollbarSize(doc) {
	  // https://developer.mozilla.org/en-US/docs/Web/API/Window/innerWidth#usage_notes
	  const documentWidth = doc.documentElement.clientWidth;
	  return Math.abs(window.innerWidth - documentWidth);
	}

	/**
	 * Gets only the valid children of a component,
	 * and ignores any nullish or falsy child.
	 *
	 * @param children the children
	 */
	function getValidReactChildren(children) {
	  return reactExports.Children.toArray(children).filter(child => /*#__PURE__*/reactExports.isValidElement(child));
	}

	function composeClasses(slots, getUtilityClass, classes = undefined) {
	  const output = {};
	  Object.keys(slots).forEach(
	  // `Object.keys(slots)` can't be wider than `T` because we infer `T` from `slots`.
	  // @ts-expect-error https://github.com/microsoft/TypeScript/pull/12253#issuecomment-263132208
	  slot => {
	    output[slot] = slots[slot].reduce((acc, key) => {
	      if (key) {
	        const utilityClass = getUtilityClass(key);
	        if (utilityClass !== '') {
	          acc.push(utilityClass);
	        }
	        if (classes && classes[key]) {
	          acc.push(classes[key]);
	        }
	      }
	      return acc;
	    }, []).join(' ');
	  });
	  return output;
	}

	const ThemeContext = /*#__PURE__*/reactExports.createContext(null);
	var ThemeContext$1 = ThemeContext;

	function useTheme$1() {
	  const theme = reactExports.useContext(ThemeContext$1);
	  return theme;
	}

	const hasSymbol = typeof Symbol === 'function' && Symbol.for;
	var nested = hasSymbol ? Symbol.for('mui.nested') : '__THEME_NESTED__';

	function mergeOuterLocalTheme(outerTheme, localTheme) {
	  if (typeof localTheme === 'function') {
	    const mergedTheme = localTheme(outerTheme);
	    return mergedTheme;
	  }
	  return _extends$1({}, outerTheme, localTheme);
	}

	/**
	 * This component takes a `theme` prop.
	 * It makes the `theme` available down the React tree thanks to React context.
	 * This component should preferably be used at **the root of your component tree**.
	 */
	function ThemeProvider$2(props) {
	  const {
	    children,
	    theme: localTheme
	  } = props;
	  const outerTheme = useTheme$1();
	  const theme = reactExports.useMemo(() => {
	    const output = outerTheme === null ? localTheme : mergeOuterLocalTheme(outerTheme, localTheme);
	    if (output != null) {
	      output[nested] = outerTheme !== null;
	    }
	    return output;
	  }, [localTheme, outerTheme]);
	  return /*#__PURE__*/jsxRuntimeExports.jsx(ThemeContext$1.Provider, {
	    value: theme,
	    children: children
	  });
	}

	const _excluded$t = ["value"];
	const RtlContext = /*#__PURE__*/reactExports.createContext();
	function RtlProvider(_ref) {
	  let {
	      value
	    } = _ref,
	    props = _objectWithoutPropertiesLoose(_ref, _excluded$t);
	  return /*#__PURE__*/jsxRuntimeExports.jsx(RtlContext.Provider, _extends$1({
	    value: value != null ? value : true
	  }, props));
	}
	const useRtl = () => {
	  const value = reactExports.useContext(RtlContext);
	  return value != null ? value : false;
	};

	const EMPTY_THEME = {};
	function useThemeScoping(themeId, upperTheme, localTheme, isPrivate = false) {
	  return reactExports.useMemo(() => {
	    const resolvedTheme = themeId ? upperTheme[themeId] || upperTheme : upperTheme;
	    if (typeof localTheme === 'function') {
	      const mergedTheme = localTheme(resolvedTheme);
	      const result = themeId ? _extends$1({}, upperTheme, {
	        [themeId]: mergedTheme
	      }) : mergedTheme;
	      // must return a function for the private theme to NOT merge with the upper theme.
	      // see the test case "use provided theme from a callback" in ThemeProvider.test.js
	      if (isPrivate) {
	        return () => result;
	      }
	      return result;
	    }
	    return themeId ? _extends$1({}, upperTheme, {
	      [themeId]: localTheme
	    }) : _extends$1({}, upperTheme, localTheme);
	  }, [themeId, upperTheme, localTheme, isPrivate]);
	}

	/**
	 * This component makes the `theme` available down the React tree.
	 * It should preferably be used at **the root of your component tree**.
	 *
	 * <ThemeProvider theme={theme}> // existing use case
	 * <ThemeProvider theme={{ id: theme }}> // theme scoping
	 */
	function ThemeProvider$1(props) {
	  const {
	    children,
	    theme: localTheme,
	    themeId
	  } = props;
	  const upperTheme = useTheme$3(EMPTY_THEME);
	  const upperPrivateTheme = useTheme$1() || EMPTY_THEME;
	  const engineTheme = useThemeScoping(themeId, upperTheme, localTheme);
	  const privateTheme = useThemeScoping(themeId, upperPrivateTheme, localTheme, true);
	  const rtlValue = engineTheme.direction === 'rtl';
	  return /*#__PURE__*/jsxRuntimeExports.jsx(ThemeProvider$2, {
	    theme: privateTheme,
	    children: /*#__PURE__*/jsxRuntimeExports.jsx(ThemeContext$2.Provider, {
	      value: engineTheme,
	      children: /*#__PURE__*/jsxRuntimeExports.jsx(RtlProvider, {
	        value: rtlValue,
	        children: children
	      })
	    })
	  });
	}

	function _typeof(o) {
	  "@babel/helpers - typeof";

	  return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) {
	    return typeof o;
	  } : function (o) {
	    return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o;
	  }, _typeof(o);
	}

	function toPrimitive(t, r) {
	  if ("object" != _typeof(t) || !t) return t;
	  var e = t[Symbol.toPrimitive];
	  if (void 0 !== e) {
	    var i = e.call(t, r || "default");
	    if ("object" != _typeof(i)) return i;
	    throw new TypeError("@@toPrimitive must return a primitive value.");
	  }
	  return ("string" === r ? String : Number)(t);
	}

	function toPropertyKey(t) {
	  var i = toPrimitive(t, "string");
	  return "symbol" == _typeof(i) ? i : i + "";
	}

	function createMixins(breakpoints, mixins) {
	  return _extends$1({
	    toolbar: {
	      minHeight: 56,
	      [breakpoints.up('xs')]: {
	        '@media (orientation: landscape)': {
	          minHeight: 48
	        }
	      },
	      [breakpoints.up('sm')]: {
	        minHeight: 64
	      }
	    }
	  }, mixins);
	}

	var colorManipulator = {};

	var interopRequireDefault = {exports: {}};

	var hasRequiredInteropRequireDefault;

	function requireInteropRequireDefault () {
		if (hasRequiredInteropRequireDefault) return interopRequireDefault.exports;
		hasRequiredInteropRequireDefault = 1;
		(function (module) {
			function _interopRequireDefault(e) {
			  return e && e.__esModule ? e : {
			    "default": e
			  };
			}
			module.exports = _interopRequireDefault, module.exports.__esModule = true, module.exports["default"] = module.exports; 
		} (interopRequireDefault));
		return interopRequireDefault.exports;
	}

	var require$$1$1 = /*@__PURE__*/getAugmentedNamespace(formatMuiErrorMessage);

	var require$$2 = /*@__PURE__*/getAugmentedNamespace(clamp);

	var hasRequiredColorManipulator;

	function requireColorManipulator () {
		if (hasRequiredColorManipulator) return colorManipulator;
		hasRequiredColorManipulator = 1;

		var _interopRequireDefault = requireInteropRequireDefault();
		Object.defineProperty(colorManipulator, "__esModule", {
		  value: true
		});
		colorManipulator.alpha = alpha;
		colorManipulator.blend = blend;
		colorManipulator.colorChannel = void 0;
		colorManipulator.darken = darken;
		colorManipulator.decomposeColor = decomposeColor;
		colorManipulator.emphasize = emphasize;
		colorManipulator.getContrastRatio = getContrastRatio;
		colorManipulator.getLuminance = getLuminance;
		colorManipulator.hexToRgb = hexToRgb;
		colorManipulator.hslToRgb = hslToRgb;
		colorManipulator.lighten = lighten;
		colorManipulator.private_safeAlpha = private_safeAlpha;
		colorManipulator.private_safeColorChannel = void 0;
		colorManipulator.private_safeDarken = private_safeDarken;
		colorManipulator.private_safeEmphasize = private_safeEmphasize;
		colorManipulator.private_safeLighten = private_safeLighten;
		colorManipulator.recomposeColor = recomposeColor;
		colorManipulator.rgbToHex = rgbToHex;
		var _formatMuiErrorMessage2 = _interopRequireDefault(require$$1$1);
		var _clamp = _interopRequireDefault(require$$2);
		/* eslint-disable @typescript-eslint/naming-convention */

		/**
		 * Returns a number whose value is limited to the given range.
		 * @param {number} value The value to be clamped
		 * @param {number} min The lower boundary of the output range
		 * @param {number} max The upper boundary of the output range
		 * @returns {number} A number in the range [min, max]
		 */
		function clampWrapper(value, min = 0, max = 1) {
		  return (0, _clamp.default)(value, min, max);
		}

		/**
		 * Converts a color from CSS hex format to CSS rgb format.
		 * @param {string} color - Hex color, i.e. #nnn or #nnnnnn
		 * @returns {string} A CSS rgb color string
		 */
		function hexToRgb(color) {
		  color = color.slice(1);
		  const re = new RegExp(`.{1,${color.length >= 6 ? 2 : 1}}`, 'g');
		  let colors = color.match(re);
		  if (colors && colors[0].length === 1) {
		    colors = colors.map(n => n + n);
		  }
		  return colors ? `rgb${colors.length === 4 ? 'a' : ''}(${colors.map((n, index) => {
	    return index < 3 ? parseInt(n, 16) : Math.round(parseInt(n, 16) / 255 * 1000) / 1000;
	  }).join(', ')})` : '';
		}
		function intToHex(int) {
		  const hex = int.toString(16);
		  return hex.length === 1 ? `0${hex}` : hex;
		}

		/**
		 * Returns an object with the type and values of a color.
		 *
		 * Note: Does not support rgb % values.
		 * @param {string} color - CSS color, i.e. one of: #nnn, #nnnnnn, rgb(), rgba(), hsl(), hsla(), color()
		 * @returns {object} - A MUI color object: {type: string, values: number[]}
		 */
		function decomposeColor(color) {
		  // Idempotent
		  if (color.type) {
		    return color;
		  }
		  if (color.charAt(0) === '#') {
		    return decomposeColor(hexToRgb(color));
		  }
		  const marker = color.indexOf('(');
		  const type = color.substring(0, marker);
		  if (['rgb', 'rgba', 'hsl', 'hsla', 'color'].indexOf(type) === -1) {
		    throw new Error((0, _formatMuiErrorMessage2.default)(9, color));
		  }
		  let values = color.substring(marker + 1, color.length - 1);
		  let colorSpace;
		  if (type === 'color') {
		    values = values.split(' ');
		    colorSpace = values.shift();
		    if (values.length === 4 && values[3].charAt(0) === '/') {
		      values[3] = values[3].slice(1);
		    }
		    if (['srgb', 'display-p3', 'a98-rgb', 'prophoto-rgb', 'rec-2020'].indexOf(colorSpace) === -1) {
		      throw new Error((0, _formatMuiErrorMessage2.default)(10, colorSpace));
		    }
		  } else {
		    values = values.split(',');
		  }
		  values = values.map(value => parseFloat(value));
		  return {
		    type,
		    values,
		    colorSpace
		  };
		}

		/**
		 * Returns a channel created from the input color.
		 *
		 * @param {string} color - CSS color, i.e. one of: #nnn, #nnnnnn, rgb(), rgba(), hsl(), hsla(), color()
		 * @returns {string} - The channel for the color, that can be used in rgba or hsla colors
		 */
		const colorChannel = color => {
		  const decomposedColor = decomposeColor(color);
		  return decomposedColor.values.slice(0, 3).map((val, idx) => decomposedColor.type.indexOf('hsl') !== -1 && idx !== 0 ? `${val}%` : val).join(' ');
		};
		colorManipulator.colorChannel = colorChannel;
		const private_safeColorChannel = (color, warning) => {
		  try {
		    return colorChannel(color);
		  } catch (error) {
		    if (warning && "production" !== 'production') {
		      console.warn(warning);
		    }
		    return color;
		  }
		};

		/**
		 * Converts a color object with type and values to a string.
		 * @param {object} color - Decomposed color
		 * @param {string} color.type - One of: 'rgb', 'rgba', 'hsl', 'hsla', 'color'
		 * @param {array} color.values - [n,n,n] or [n,n,n,n]
		 * @returns {string} A CSS color string
		 */
		colorManipulator.private_safeColorChannel = private_safeColorChannel;
		function recomposeColor(color) {
		  const {
		    type,
		    colorSpace
		  } = color;
		  let {
		    values
		  } = color;
		  if (type.indexOf('rgb') !== -1) {
		    // Only convert the first 3 values to int (i.e. not alpha)
		    values = values.map((n, i) => i < 3 ? parseInt(n, 10) : n);
		  } else if (type.indexOf('hsl') !== -1) {
		    values[1] = `${values[1]}%`;
		    values[2] = `${values[2]}%`;
		  }
		  if (type.indexOf('color') !== -1) {
		    values = `${colorSpace} ${values.join(' ')}`;
		  } else {
		    values = `${values.join(', ')}`;
		  }
		  return `${type}(${values})`;
		}

		/**
		 * Converts a color from CSS rgb format to CSS hex format.
		 * @param {string} color - RGB color, i.e. rgb(n, n, n)
		 * @returns {string} A CSS rgb color string, i.e. #nnnnnn
		 */
		function rgbToHex(color) {
		  // Idempotent
		  if (color.indexOf('#') === 0) {
		    return color;
		  }
		  const {
		    values
		  } = decomposeColor(color);
		  return `#${values.map((n, i) => intToHex(i === 3 ? Math.round(255 * n) : n)).join('')}`;
		}

		/**
		 * Converts a color from hsl format to rgb format.
		 * @param {string} color - HSL color values
		 * @returns {string} rgb color values
		 */
		function hslToRgb(color) {
		  color = decomposeColor(color);
		  const {
		    values
		  } = color;
		  const h = values[0];
		  const s = values[1] / 100;
		  const l = values[2] / 100;
		  const a = s * Math.min(l, 1 - l);
		  const f = (n, k = (n + h / 30) % 12) => l - a * Math.max(Math.min(k - 3, 9 - k, 1), -1);
		  let type = 'rgb';
		  const rgb = [Math.round(f(0) * 255), Math.round(f(8) * 255), Math.round(f(4) * 255)];
		  if (color.type === 'hsla') {
		    type += 'a';
		    rgb.push(values[3]);
		  }
		  return recomposeColor({
		    type,
		    values: rgb
		  });
		}
		/**
		 * The relative brightness of any point in a color space,
		 * normalized to 0 for darkest black and 1 for lightest white.
		 *
		 * Formula: https://www.w3.org/TR/WCAG20-TECHS/G17.html#G17-tests
		 * @param {string} color - CSS color, i.e. one of: #nnn, #nnnnnn, rgb(), rgba(), hsl(), hsla(), color()
		 * @returns {number} The relative brightness of the color in the range 0 - 1
		 */
		function getLuminance(color) {
		  color = decomposeColor(color);
		  let rgb = color.type === 'hsl' || color.type === 'hsla' ? decomposeColor(hslToRgb(color)).values : color.values;
		  rgb = rgb.map(val => {
		    if (color.type !== 'color') {
		      val /= 255; // normalized
		    }
		    return val <= 0.03928 ? val / 12.92 : ((val + 0.055) / 1.055) ** 2.4;
		  });

		  // Truncate at 3 digits
		  return Number((0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2]).toFixed(3));
		}

		/**
		 * Calculates the contrast ratio between two colors.
		 *
		 * Formula: https://www.w3.org/TR/WCAG20-TECHS/G17.html#G17-tests
		 * @param {string} foreground - CSS color, i.e. one of: #nnn, #nnnnnn, rgb(), rgba(), hsl(), hsla()
		 * @param {string} background - CSS color, i.e. one of: #nnn, #nnnnnn, rgb(), rgba(), hsl(), hsla()
		 * @returns {number} A contrast ratio value in the range 0 - 21.
		 */
		function getContrastRatio(foreground, background) {
		  const lumA = getLuminance(foreground);
		  const lumB = getLuminance(background);
		  return (Math.max(lumA, lumB) + 0.05) / (Math.min(lumA, lumB) + 0.05);
		}

		/**
		 * Sets the absolute transparency of a color.
		 * Any existing alpha values are overwritten.
		 * @param {string} color - CSS color, i.e. one of: #nnn, #nnnnnn, rgb(), rgba(), hsl(), hsla(), color()
		 * @param {number} value - value to set the alpha channel to in the range 0 - 1
		 * @returns {string} A CSS color string. Hex input values are returned as rgb
		 */
		function alpha(color, value) {
		  color = decomposeColor(color);
		  value = clampWrapper(value);
		  if (color.type === 'rgb' || color.type === 'hsl') {
		    color.type += 'a';
		  }
		  if (color.type === 'color') {
		    color.values[3] = `/${value}`;
		  } else {
		    color.values[3] = value;
		  }
		  return recomposeColor(color);
		}
		function private_safeAlpha(color, value, warning) {
		  try {
		    return alpha(color, value);
		  } catch (error) {
		    if (warning && "production" !== 'production') {
		      console.warn(warning);
		    }
		    return color;
		  }
		}

		/**
		 * Darkens a color.
		 * @param {string} color - CSS color, i.e. one of: #nnn, #nnnnnn, rgb(), rgba(), hsl(), hsla(), color()
		 * @param {number} coefficient - multiplier in the range 0 - 1
		 * @returns {string} A CSS color string. Hex input values are returned as rgb
		 */
		function darken(color, coefficient) {
		  color = decomposeColor(color);
		  coefficient = clampWrapper(coefficient);
		  if (color.type.indexOf('hsl') !== -1) {
		    color.values[2] *= 1 - coefficient;
		  } else if (color.type.indexOf('rgb') !== -1 || color.type.indexOf('color') !== -1) {
		    for (let i = 0; i < 3; i += 1) {
		      color.values[i] *= 1 - coefficient;
		    }
		  }
		  return recomposeColor(color);
		}
		function private_safeDarken(color, coefficient, warning) {
		  try {
		    return darken(color, coefficient);
		  } catch (error) {
		    if (warning && "production" !== 'production') {
		      console.warn(warning);
		    }
		    return color;
		  }
		}

		/**
		 * Lightens a color.
		 * @param {string} color - CSS color, i.e. one of: #nnn, #nnnnnn, rgb(), rgba(), hsl(), hsla(), color()
		 * @param {number} coefficient - multiplier in the range 0 - 1
		 * @returns {string} A CSS color string. Hex input values are returned as rgb
		 */
		function lighten(color, coefficient) {
		  color = decomposeColor(color);
		  coefficient = clampWrapper(coefficient);
		  if (color.type.indexOf('hsl') !== -1) {
		    color.values[2] += (100 - color.values[2]) * coefficient;
		  } else if (color.type.indexOf('rgb') !== -1) {
		    for (let i = 0; i < 3; i += 1) {
		      color.values[i] += (255 - color.values[i]) * coefficient;
		    }
		  } else if (color.type.indexOf('color') !== -1) {
		    for (let i = 0; i < 3; i += 1) {
		      color.values[i] += (1 - color.values[i]) * coefficient;
		    }
		  }
		  return recomposeColor(color);
		}
		function private_safeLighten(color, coefficient, warning) {
		  try {
		    return lighten(color, coefficient);
		  } catch (error) {
		    if (warning && "production" !== 'production') {
		      console.warn(warning);
		    }
		    return color;
		  }
		}

		/**
		 * Darken or lighten a color, depending on its luminance.
		 * Light colors are darkened, dark colors are lightened.
		 * @param {string} color - CSS color, i.e. one of: #nnn, #nnnnnn, rgb(), rgba(), hsl(), hsla(), color()
		 * @param {number} coefficient=0.15 - multiplier in the range 0 - 1
		 * @returns {string} A CSS color string. Hex input values are returned as rgb
		 */
		function emphasize(color, coefficient = 0.15) {
		  return getLuminance(color) > 0.5 ? darken(color, coefficient) : lighten(color, coefficient);
		}
		function private_safeEmphasize(color, coefficient, warning) {
		  try {
		    return emphasize(color, coefficient);
		  } catch (error) {
		    if (warning && "production" !== 'production') {
		      console.warn(warning);
		    }
		    return color;
		  }
		}

		/**
		 * Blend a transparent overlay color with a background color, resulting in a single
		 * RGB color.
		 * @param {string} background - CSS color
		 * @param {string} overlay - CSS color
		 * @param {number} opacity - Opacity multiplier in the range 0 - 1
		 * @param {number} [gamma=1.0] - Gamma correction factor. For gamma-correct blending, 2.2 is usual.
		 */
		function blend(background, overlay, opacity, gamma = 1.0) {
		  const blendChannel = (b, o) => Math.round((b ** (1 / gamma) * (1 - opacity) + o ** (1 / gamma) * opacity) ** gamma);
		  const backgroundColor = decomposeColor(background);
		  const overlayColor = decomposeColor(overlay);
		  const rgb = [blendChannel(backgroundColor.values[0], overlayColor.values[0]), blendChannel(backgroundColor.values[1], overlayColor.values[1]), blendChannel(backgroundColor.values[2], overlayColor.values[2])];
		  return recomposeColor({
		    type: 'rgb',
		    values: rgb
		  });
		}
		return colorManipulator;
	}

	var colorManipulatorExports = /*@__PURE__*/ requireColorManipulator();

	const _excluded$s = ["mode", "contrastThreshold", "tonalOffset"];
	const light = {
	  // The colors used to style the text.
	  text: {
	    // The most important text.
	    primary: 'rgba(0, 0, 0, 0.87)',
	    // Secondary text.
	    secondary: 'rgba(0, 0, 0, 0.6)',
	    // Disabled text have even lower visual prominence.
	    disabled: 'rgba(0, 0, 0, 0.38)'
	  },
	  // The color used to divide different elements.
	  divider: 'rgba(0, 0, 0, 0.12)',
	  // The background colors used to style the surfaces.
	  // Consistency between these values is important.
	  background: {
	    paper: common$1.white,
	    default: common$1.white
	  },
	  // The colors used to style the action elements.
	  action: {
	    // The color of an active action like an icon button.
	    active: 'rgba(0, 0, 0, 0.54)',
	    // The color of an hovered action.
	    hover: 'rgba(0, 0, 0, 0.04)',
	    hoverOpacity: 0.04,
	    // The color of a selected action.
	    selected: 'rgba(0, 0, 0, 0.08)',
	    selectedOpacity: 0.08,
	    // The color of a disabled action.
	    disabled: 'rgba(0, 0, 0, 0.26)',
	    // The background color of a disabled action.
	    disabledBackground: 'rgba(0, 0, 0, 0.12)',
	    disabledOpacity: 0.38,
	    focus: 'rgba(0, 0, 0, 0.12)',
	    focusOpacity: 0.12,
	    activatedOpacity: 0.12
	  }
	};
	const dark = {
	  text: {
	    primary: common$1.white,
	    secondary: 'rgba(255, 255, 255, 0.7)',
	    disabled: 'rgba(255, 255, 255, 0.5)',
	    icon: 'rgba(255, 255, 255, 0.5)'
	  },
	  divider: 'rgba(255, 255, 255, 0.12)',
	  background: {
	    paper: '#121212',
	    default: '#121212'
	  },
	  action: {
	    active: common$1.white,
	    hover: 'rgba(255, 255, 255, 0.08)',
	    hoverOpacity: 0.08,
	    selected: 'rgba(255, 255, 255, 0.16)',
	    selectedOpacity: 0.16,
	    disabled: 'rgba(255, 255, 255, 0.3)',
	    disabledBackground: 'rgba(255, 255, 255, 0.12)',
	    disabledOpacity: 0.38,
	    focus: 'rgba(255, 255, 255, 0.12)',
	    focusOpacity: 0.12,
	    activatedOpacity: 0.24
	  }
	};
	function addLightOrDark(intent, direction, shade, tonalOffset) {
	  const tonalOffsetLight = tonalOffset.light || tonalOffset;
	  const tonalOffsetDark = tonalOffset.dark || tonalOffset * 1.5;
	  if (!intent[direction]) {
	    if (intent.hasOwnProperty(shade)) {
	      intent[direction] = intent[shade];
	    } else if (direction === 'light') {
	      intent.light = colorManipulatorExports.lighten(intent.main, tonalOffsetLight);
	    } else if (direction === 'dark') {
	      intent.dark = colorManipulatorExports.darken(intent.main, tonalOffsetDark);
	    }
	  }
	}
	function getDefaultPrimary(mode = 'light') {
	  if (mode === 'dark') {
	    return {
	      main: blue$1[200],
	      light: blue$1[50],
	      dark: blue$1[400]
	    };
	  }
	  return {
	    main: blue$1[700],
	    light: blue$1[400],
	    dark: blue$1[800]
	  };
	}
	function getDefaultSecondary(mode = 'light') {
	  if (mode === 'dark') {
	    return {
	      main: purple$1[200],
	      light: purple$1[50],
	      dark: purple$1[400]
	    };
	  }
	  return {
	    main: purple$1[500],
	    light: purple$1[300],
	    dark: purple$1[700]
	  };
	}
	function getDefaultError(mode = 'light') {
	  if (mode === 'dark') {
	    return {
	      main: red$1[500],
	      light: red$1[300],
	      dark: red$1[700]
	    };
	  }
	  return {
	    main: red$1[700],
	    light: red$1[400],
	    dark: red$1[800]
	  };
	}
	function getDefaultInfo(mode = 'light') {
	  if (mode === 'dark') {
	    return {
	      main: lightBlue$1[400],
	      light: lightBlue$1[300],
	      dark: lightBlue$1[700]
	    };
	  }
	  return {
	    main: lightBlue$1[700],
	    light: lightBlue$1[500],
	    dark: lightBlue$1[900]
	  };
	}
	function getDefaultSuccess(mode = 'light') {
	  if (mode === 'dark') {
	    return {
	      main: green$1[400],
	      light: green$1[300],
	      dark: green$1[700]
	    };
	  }
	  return {
	    main: green$1[800],
	    light: green$1[500],
	    dark: green$1[900]
	  };
	}
	function getDefaultWarning(mode = 'light') {
	  if (mode === 'dark') {
	    return {
	      main: orange$1[400],
	      light: orange$1[300],
	      dark: orange$1[700]
	    };
	  }
	  return {
	    main: '#ed6c02',
	    // closest to orange[800] that pass 3:1.
	    light: orange$1[500],
	    dark: orange$1[900]
	  };
	}
	function createPalette(palette) {
	  const {
	      mode = 'light',
	      contrastThreshold = 3,
	      tonalOffset = 0.2
	    } = palette,
	    other = _objectWithoutPropertiesLoose(palette, _excluded$s);
	  const primary = palette.primary || getDefaultPrimary(mode);
	  const secondary = palette.secondary || getDefaultSecondary(mode);
	  const error = palette.error || getDefaultError(mode);
	  const info = palette.info || getDefaultInfo(mode);
	  const success = palette.success || getDefaultSuccess(mode);
	  const warning = palette.warning || getDefaultWarning(mode);

	  // Use the same logic as
	  // Bootstrap: https://github.com/twbs/bootstrap/blob/1d6e3710dd447de1a200f29e8fa521f8a0908f70/scss/_functions.scss#L59
	  // and material-components-web https://github.com/material-components/material-components-web/blob/ac46b8863c4dab9fc22c4c662dc6bd1b65dd652f/packages/mdc-theme/_functions.scss#L54
	  function getContrastText(background) {
	    const contrastText = colorManipulatorExports.getContrastRatio(background, dark.text.primary) >= contrastThreshold ? dark.text.primary : light.text.primary;
	    return contrastText;
	  }
	  const augmentColor = ({
	    color,
	    name,
	    mainShade = 500,
	    lightShade = 300,
	    darkShade = 700
	  }) => {
	    color = _extends$1({}, color);
	    if (!color.main && color[mainShade]) {
	      color.main = color[mainShade];
	    }
	    if (!color.hasOwnProperty('main')) {
	      throw new Error(formatMuiErrorMessage$1(11, name ? ` (${name})` : '', mainShade));
	    }
	    if (typeof color.main !== 'string') {
	      throw new Error(formatMuiErrorMessage$1(12, name ? ` (${name})` : '', JSON.stringify(color.main)));
	    }
	    addLightOrDark(color, 'light', lightShade, tonalOffset);
	    addLightOrDark(color, 'dark', darkShade, tonalOffset);
	    if (!color.contrastText) {
	      color.contrastText = getContrastText(color.main);
	    }
	    return color;
	  };
	  const modes = {
	    dark,
	    light
	  };
	  const paletteOutput = deepmerge$1(_extends$1({
	    // A collection of common colors.
	    common: _extends$1({}, common$1),
	    // prevent mutable object.
	    // The palette mode, can be light or dark.
	    mode,
	    // The colors used to represent primary interface elements for a user.
	    primary: augmentColor({
	      color: primary,
	      name: 'primary'
	    }),
	    // The colors used to represent secondary interface elements for a user.
	    secondary: augmentColor({
	      color: secondary,
	      name: 'secondary',
	      mainShade: 'A400',
	      lightShade: 'A200',
	      darkShade: 'A700'
	    }),
	    // The colors used to represent interface elements that the user should be made aware of.
	    error: augmentColor({
	      color: error,
	      name: 'error'
	    }),
	    // The colors used to represent potentially dangerous actions or important messages.
	    warning: augmentColor({
	      color: warning,
	      name: 'warning'
	    }),
	    // The colors used to present information to the user that is neutral and not necessarily important.
	    info: augmentColor({
	      color: info,
	      name: 'info'
	    }),
	    // The colors used to indicate the successful completion of an action that user triggered.
	    success: augmentColor({
	      color: success,
	      name: 'success'
	    }),
	    // The grey colors.
	    grey: grey$1,
	    // Used by `getContrastText()` to maximize the contrast between
	    // the background and the text.
	    contrastThreshold,
	    // Takes a background color and returns the text color that maximizes the contrast.
	    getContrastText,
	    // Generate a rich color object.
	    augmentColor,
	    // Used by the functions below to shift a color's luminance by approximately
	    // two indexes within its tonal palette.
	    // E.g., shift from Red 500 to Red 300 or Red 700.
	    tonalOffset
	  }, modes[mode]), other);
	  return paletteOutput;
	}

	const _excluded$r = ["fontFamily", "fontSize", "fontWeightLight", "fontWeightRegular", "fontWeightMedium", "fontWeightBold", "htmlFontSize", "allVariants", "pxToRem"];
	function round(value) {
	  return Math.round(value * 1e5) / 1e5;
	}
	const caseAllCaps = {
	  textTransform: 'uppercase'
	};
	const defaultFontFamily = '"Roboto", "Helvetica", "Arial", sans-serif';

	/**
	 * @see @link{https://m2.material.io/design/typography/the-type-system.html}
	 * @see @link{https://m2.material.io/design/typography/understanding-typography.html}
	 */
	function createTypography(palette, typography) {
	  const _ref = typeof typography === 'function' ? typography(palette) : typography,
	    {
	      fontFamily = defaultFontFamily,
	      // The default font size of the Material Specification.
	      fontSize = 14,
	      // px
	      fontWeightLight = 300,
	      fontWeightRegular = 400,
	      fontWeightMedium = 500,
	      fontWeightBold = 700,
	      // Tell MUI what's the font-size on the html element.
	      // 16px is the default font-size used by browsers.
	      htmlFontSize = 16,
	      // Apply the CSS properties to all the variants.
	      allVariants,
	      pxToRem: pxToRem2
	    } = _ref,
	    other = _objectWithoutPropertiesLoose(_ref, _excluded$r);
	  const coef = fontSize / 14;
	  const pxToRem = pxToRem2 || (size => `${size / htmlFontSize * coef}rem`);
	  const buildVariant = (fontWeight, size, lineHeight, letterSpacing, casing) => _extends$1({
	    fontFamily,
	    fontWeight,
	    fontSize: pxToRem(size),
	    // Unitless following https://meyerweb.com/eric/thoughts/2006/02/08/unitless-line-heights/
	    lineHeight
	  }, fontFamily === defaultFontFamily ? {
	    letterSpacing: `${round(letterSpacing / size)}em`
	  } : {}, casing, allVariants);
	  const variants = {
	    h1: buildVariant(fontWeightLight, 96, 1.167, -1.5),
	    h2: buildVariant(fontWeightLight, 60, 1.2, -0.5),
	    h3: buildVariant(fontWeightRegular, 48, 1.167, 0),
	    h4: buildVariant(fontWeightRegular, 34, 1.235, 0.25),
	    h5: buildVariant(fontWeightRegular, 24, 1.334, 0),
	    h6: buildVariant(fontWeightMedium, 20, 1.6, 0.15),
	    subtitle1: buildVariant(fontWeightRegular, 16, 1.75, 0.15),
	    subtitle2: buildVariant(fontWeightMedium, 14, 1.57, 0.1),
	    body1: buildVariant(fontWeightRegular, 16, 1.5, 0.15),
	    body2: buildVariant(fontWeightRegular, 14, 1.43, 0.15),
	    button: buildVariant(fontWeightMedium, 14, 1.75, 0.4, caseAllCaps),
	    caption: buildVariant(fontWeightRegular, 12, 1.66, 0.4),
	    overline: buildVariant(fontWeightRegular, 12, 2.66, 1, caseAllCaps),
	    // TODO v6: Remove handling of 'inherit' variant from the theme as it is already handled in Material UI's Typography component. Also, remember to remove the associated types.
	    inherit: {
	      fontFamily: 'inherit',
	      fontWeight: 'inherit',
	      fontSize: 'inherit',
	      lineHeight: 'inherit',
	      letterSpacing: 'inherit'
	    }
	  };
	  return deepmerge$1(_extends$1({
	    htmlFontSize,
	    pxToRem,
	    fontFamily,
	    fontSize,
	    fontWeightLight,
	    fontWeightRegular,
	    fontWeightMedium,
	    fontWeightBold
	  }, variants), other, {
	    clone: false // No need to clone deep
	  });
	}

	const shadowKeyUmbraOpacity = 0.2;
	const shadowKeyPenumbraOpacity = 0.14;
	const shadowAmbientShadowOpacity = 0.12;
	function createShadow(...px) {
	  return [`${px[0]}px ${px[1]}px ${px[2]}px ${px[3]}px rgba(0,0,0,${shadowKeyUmbraOpacity})`, `${px[4]}px ${px[5]}px ${px[6]}px ${px[7]}px rgba(0,0,0,${shadowKeyPenumbraOpacity})`, `${px[8]}px ${px[9]}px ${px[10]}px ${px[11]}px rgba(0,0,0,${shadowAmbientShadowOpacity})`].join(',');
	}

	// Values from https://github.com/material-components/material-components-web/blob/be8747f94574669cb5e7add1a7c54fa41a89cec7/packages/mdc-elevation/_variables.scss
	const shadows = ['none', createShadow(0, 2, 1, -1, 0, 1, 1, 0, 0, 1, 3, 0), createShadow(0, 3, 1, -2, 0, 2, 2, 0, 0, 1, 5, 0), createShadow(0, 3, 3, -2, 0, 3, 4, 0, 0, 1, 8, 0), createShadow(0, 2, 4, -1, 0, 4, 5, 0, 0, 1, 10, 0), createShadow(0, 3, 5, -1, 0, 5, 8, 0, 0, 1, 14, 0), createShadow(0, 3, 5, -1, 0, 6, 10, 0, 0, 1, 18, 0), createShadow(0, 4, 5, -2, 0, 7, 10, 1, 0, 2, 16, 1), createShadow(0, 5, 5, -3, 0, 8, 10, 1, 0, 3, 14, 2), createShadow(0, 5, 6, -3, 0, 9, 12, 1, 0, 3, 16, 2), createShadow(0, 6, 6, -3, 0, 10, 14, 1, 0, 4, 18, 3), createShadow(0, 6, 7, -4, 0, 11, 15, 1, 0, 4, 20, 3), createShadow(0, 7, 8, -4, 0, 12, 17, 2, 0, 5, 22, 4), createShadow(0, 7, 8, -4, 0, 13, 19, 2, 0, 5, 24, 4), createShadow(0, 7, 9, -4, 0, 14, 21, 2, 0, 5, 26, 4), createShadow(0, 8, 9, -5, 0, 15, 22, 2, 0, 6, 28, 5), createShadow(0, 8, 10, -5, 0, 16, 24, 2, 0, 6, 30, 5), createShadow(0, 8, 11, -5, 0, 17, 26, 2, 0, 6, 32, 5), createShadow(0, 9, 11, -5, 0, 18, 28, 2, 0, 7, 34, 6), createShadow(0, 9, 12, -6, 0, 19, 29, 2, 0, 7, 36, 6), createShadow(0, 10, 13, -6, 0, 20, 31, 3, 0, 8, 38, 7), createShadow(0, 10, 13, -6, 0, 21, 33, 3, 0, 8, 40, 7), createShadow(0, 10, 14, -6, 0, 22, 35, 3, 0, 8, 42, 7), createShadow(0, 11, 14, -7, 0, 23, 36, 3, 0, 9, 44, 8), createShadow(0, 11, 15, -7, 0, 24, 38, 3, 0, 9, 46, 8)];
	var shadows$1 = shadows;

	const _excluded$q = ["duration", "easing", "delay"];
	// Follow https://material.google.com/motion/duration-easing.html#duration-easing-natural-easing-curves
	// to learn the context in which each easing should be used.
	const easing = {
	  // This is the most common easing curve.
	  easeInOut: 'cubic-bezier(0.4, 0, 0.2, 1)',
	  // Objects enter the screen at full velocity from off-screen and
	  // slowly decelerate to a resting point.
	  easeOut: 'cubic-bezier(0.0, 0, 0.2, 1)',
	  // Objects leave the screen at full velocity. They do not decelerate when off-screen.
	  easeIn: 'cubic-bezier(0.4, 0, 1, 1)',
	  // The sharp curve is used by objects that may return to the screen at any time.
	  sharp: 'cubic-bezier(0.4, 0, 0.6, 1)'
	};

	// Follow https://m2.material.io/guidelines/motion/duration-easing.html#duration-easing-common-durations
	// to learn when use what timing
	const duration = {
	  shortest: 150,
	  shorter: 200,
	  short: 250,
	  // most basic recommended timing
	  standard: 300,
	  // this is to be used in complex animations
	  complex: 375,
	  // recommended when something is entering screen
	  enteringScreen: 225,
	  // recommended when something is leaving screen
	  leavingScreen: 195
	};
	function formatMs(milliseconds) {
	  return `${Math.round(milliseconds)}ms`;
	}
	function getAutoHeightDuration(height) {
	  if (!height) {
	    return 0;
	  }
	  const constant = height / 36;

	  // https://www.wolframalpha.com/input/?i=(4+%2B+15+*+(x+%2F+36+)+**+0.25+%2B+(x+%2F+36)+%2F+5)+*+10
	  return Math.round((4 + 15 * constant ** 0.25 + constant / 5) * 10);
	}
	function createTransitions(inputTransitions) {
	  const mergedEasing = _extends$1({}, easing, inputTransitions.easing);
	  const mergedDuration = _extends$1({}, duration, inputTransitions.duration);
	  const create = (props = ['all'], options = {}) => {
	    const {
	        duration: durationOption = mergedDuration.standard,
	        easing: easingOption = mergedEasing.easeInOut,
	        delay = 0
	      } = options;
	      _objectWithoutPropertiesLoose(options, _excluded$q);
	    return (Array.isArray(props) ? props : [props]).map(animatedProp => `${animatedProp} ${typeof durationOption === 'string' ? durationOption : formatMs(durationOption)} ${easingOption} ${typeof delay === 'string' ? delay : formatMs(delay)}`).join(',');
	  };
	  return _extends$1({
	    getAutoHeightDuration,
	    create
	  }, inputTransitions, {
	    easing: mergedEasing,
	    duration: mergedDuration
	  });
	}

	// We need to centralize the zIndex definitions as they work
	// like global values in the browser.
	const zIndex = {
	  mobileStepper: 1000,
	  fab: 1050,
	  speedDial: 1050,
	  appBar: 1100,
	  drawer: 1200,
	  modal: 1300,
	  snackbar: 1400,
	  tooltip: 1500
	};
	var zIndex$1 = zIndex;

	const _excluded$p = ["breakpoints", "mixins", "spacing", "palette", "transitions", "typography", "shape"];
	function createTheme(options = {}, ...args) {
	  const {
	      mixins: mixinsInput = {},
	      palette: paletteInput = {},
	      transitions: transitionsInput = {},
	      typography: typographyInput = {}
	    } = options,
	    other = _objectWithoutPropertiesLoose(options, _excluded$p);
	  if (options.vars) {
	    throw new Error(formatMuiErrorMessage$1(18));
	  }
	  const palette = createPalette(paletteInput);
	  const systemTheme = createTheme$2(options);
	  let muiTheme = deepmerge$1(systemTheme, {
	    mixins: createMixins(systemTheme.breakpoints, mixinsInput),
	    palette,
	    // Don't use [...shadows] until you've verified its transpiled code is not invoking the iterator protocol.
	    shadows: shadows$1.slice(),
	    typography: createTypography(palette, typographyInput),
	    transitions: createTransitions(transitionsInput),
	    zIndex: _extends$1({}, zIndex$1)
	  });
	  muiTheme = deepmerge$1(muiTheme, other);
	  muiTheme = args.reduce((acc, argument) => deepmerge$1(acc, argument), muiTheme);
	  muiTheme.unstable_sxConfig = _extends$1({}, defaultSxConfig$1, other == null ? void 0 : other.unstable_sxConfig);
	  muiTheme.unstable_sx = function sx(props) {
	    return styleFunctionSx$2({
	      sx: props,
	      theme: this
	    });
	  };
	  return muiTheme;
	}

	const defaultTheme = createTheme();
	var defaultTheme$1 = defaultTheme;

	function useTheme() {
	  const theme = useTheme$2(defaultTheme$1);
	  return theme[THEME_ID] || theme;
	}

	function useThemeProps({
	  props,
	  name
	}) {
	  return useThemeProps$1({
	    props,
	    name,
	    defaultTheme: defaultTheme$1,
	    themeId: THEME_ID
	  });
	}

	var createStyled$1 = {};

	var _extends = {exports: {}};

	var hasRequired_extends;

	function require_extends () {
		if (hasRequired_extends) return _extends.exports;
		hasRequired_extends = 1;
		(function (module) {
			function _extends() {
			  return module.exports = _extends = Object.assign ? Object.assign.bind() : function (n) {
			    for (var e = 1; e < arguments.length; e++) {
			      var t = arguments[e];
			      for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]);
			    }
			    return n;
			  }, module.exports.__esModule = true, module.exports["default"] = module.exports, _extends.apply(null, arguments);
			}
			module.exports = _extends, module.exports.__esModule = true, module.exports["default"] = module.exports; 
		} (_extends));
		return _extends.exports;
	}

	var objectWithoutPropertiesLoose = {exports: {}};

	var hasRequiredObjectWithoutPropertiesLoose;

	function requireObjectWithoutPropertiesLoose () {
		if (hasRequiredObjectWithoutPropertiesLoose) return objectWithoutPropertiesLoose.exports;
		hasRequiredObjectWithoutPropertiesLoose = 1;
		(function (module) {
			function _objectWithoutPropertiesLoose(r, e) {
			  if (null == r) return {};
			  var t = {};
			  for (var n in r) if ({}.hasOwnProperty.call(r, n)) {
			    if (-1 !== e.indexOf(n)) continue;
			    t[n] = r[n];
			  }
			  return t;
			}
			module.exports = _objectWithoutPropertiesLoose, module.exports.__esModule = true, module.exports["default"] = module.exports; 
		} (objectWithoutPropertiesLoose));
		return objectWithoutPropertiesLoose.exports;
	}

	var require$$1 = /*@__PURE__*/getAugmentedNamespace(styledEngine);

	var require$$4 = /*@__PURE__*/getAugmentedNamespace(deepmerge);

	var require$$5 = /*@__PURE__*/getAugmentedNamespace(capitalize$1);

	var require$$6 = /*@__PURE__*/getAugmentedNamespace(getDisplayName);

	var require$$7 = /*@__PURE__*/getAugmentedNamespace(createTheme$1);

	var require$$8 = /*@__PURE__*/getAugmentedNamespace(styleFunctionSx);

	var hasRequiredCreateStyled;

	function requireCreateStyled () {
		if (hasRequiredCreateStyled) return createStyled$1;
		hasRequiredCreateStyled = 1;

		var _interopRequireDefault = requireInteropRequireDefault();
		Object.defineProperty(createStyled$1, "__esModule", {
		  value: true
		});
		createStyled$1.default = createStyled;
		createStyled$1.shouldForwardProp = shouldForwardProp;
		createStyled$1.systemDefaultTheme = void 0;
		var _extends2 = _interopRequireDefault(require_extends());
		var _objectWithoutPropertiesLoose2 = _interopRequireDefault(requireObjectWithoutPropertiesLoose());
		var _styledEngine = _interopRequireWildcard(require$$1);
		var _deepmerge = require$$4;
		_interopRequireDefault(require$$5);
		_interopRequireDefault(require$$6);
		var _createTheme = _interopRequireDefault(require$$7);
		var _styleFunctionSx = _interopRequireDefault(require$$8);
		const _excluded = ["ownerState"],
		  _excluded2 = ["variants"],
		  _excluded3 = ["name", "slot", "skipVariantsResolver", "skipSx", "overridesResolver"];
		/* eslint-disable no-underscore-dangle */
		function _getRequireWildcardCache(e) {
		  if ("function" != typeof WeakMap) return null;
		  var r = new WeakMap(),
		    t = new WeakMap();
		  return (_getRequireWildcardCache = function (e) {
		    return e ? t : r;
		  })(e);
		}
		function _interopRequireWildcard(e, r) {
		  if (!r && e && e.__esModule) return e;
		  if (null === e || "object" != typeof e && "function" != typeof e) return {
		    default: e
		  };
		  var t = _getRequireWildcardCache(r);
		  if (t && t.has(e)) return t.get(e);
		  var n = {
		      __proto__: null
		    },
		    a = Object.defineProperty && Object.getOwnPropertyDescriptor;
		  for (var u in e) if ("default" !== u && Object.prototype.hasOwnProperty.call(e, u)) {
		    var i = a ? Object.getOwnPropertyDescriptor(e, u) : null;
		    i && (i.get || i.set) ? Object.defineProperty(n, u, i) : n[u] = e[u];
		  }
		  return n.default = e, t && t.set(e, n), n;
		}
		function isEmpty(obj) {
		  return Object.keys(obj).length === 0;
		}

		// https://github.com/emotion-js/emotion/blob/26ded6109fcd8ca9875cc2ce4564fee678a3f3c5/packages/styled/src/utils.js#L40
		function isStringTag(tag) {
		  return typeof tag === 'string' &&
		  // 96 is one less than the char code
		  // for "a" so this is checking that
		  // it's a lowercase character
		  tag.charCodeAt(0) > 96;
		}

		// Update /system/styled/#api in case if this changes
		function shouldForwardProp(prop) {
		  return prop !== 'ownerState' && prop !== 'theme' && prop !== 'sx' && prop !== 'as';
		}
		const systemDefaultTheme = createStyled$1.systemDefaultTheme = (0, _createTheme.default)();
		const lowercaseFirstLetter = string => {
		  if (!string) {
		    return string;
		  }
		  return string.charAt(0).toLowerCase() + string.slice(1);
		};
		function resolveTheme({
		  defaultTheme,
		  theme,
		  themeId
		}) {
		  return isEmpty(theme) ? defaultTheme : theme[themeId] || theme;
		}
		function defaultOverridesResolver(slot) {
		  if (!slot) {
		    return null;
		  }
		  return (props, styles) => styles[slot];
		}
		function processStyleArg(callableStyle, _ref) {
		  let {
		      ownerState
		    } = _ref,
		    props = (0, _objectWithoutPropertiesLoose2.default)(_ref, _excluded);
		  const resolvedStylesArg = typeof callableStyle === 'function' ? callableStyle((0, _extends2.default)({
		    ownerState
		  }, props)) : callableStyle;
		  if (Array.isArray(resolvedStylesArg)) {
		    return resolvedStylesArg.flatMap(resolvedStyle => processStyleArg(resolvedStyle, (0, _extends2.default)({
		      ownerState
		    }, props)));
		  }
		  if (!!resolvedStylesArg && typeof resolvedStylesArg === 'object' && Array.isArray(resolvedStylesArg.variants)) {
		    const {
		        variants = []
		      } = resolvedStylesArg,
		      otherStyles = (0, _objectWithoutPropertiesLoose2.default)(resolvedStylesArg, _excluded2);
		    let result = otherStyles;
		    variants.forEach(variant => {
		      let isMatch = true;
		      if (typeof variant.props === 'function') {
		        isMatch = variant.props((0, _extends2.default)({
		          ownerState
		        }, props, ownerState));
		      } else {
		        Object.keys(variant.props).forEach(key => {
		          if ((ownerState == null ? void 0 : ownerState[key]) !== variant.props[key] && props[key] !== variant.props[key]) {
		            isMatch = false;
		          }
		        });
		      }
		      if (isMatch) {
		        if (!Array.isArray(result)) {
		          result = [result];
		        }
		        result.push(typeof variant.style === 'function' ? variant.style((0, _extends2.default)({
		          ownerState
		        }, props, ownerState)) : variant.style);
		      }
		    });
		    return result;
		  }
		  return resolvedStylesArg;
		}
		function createStyled(input = {}) {
		  const {
		    themeId,
		    defaultTheme = systemDefaultTheme,
		    rootShouldForwardProp = shouldForwardProp,
		    slotShouldForwardProp = shouldForwardProp
		  } = input;
		  const systemSx = props => {
		    return (0, _styleFunctionSx.default)((0, _extends2.default)({}, props, {
		      theme: resolveTheme((0, _extends2.default)({}, props, {
		        defaultTheme,
		        themeId
		      }))
		    }));
		  };
		  systemSx.__mui_systemSx = true;
		  return (tag, inputOptions = {}) => {
		    // Filter out the `sx` style function from the previous styled component to prevent unnecessary styles generated by the composite components.
		    (0, _styledEngine.internal_processStyles)(tag, styles => styles.filter(style => !(style != null && style.__mui_systemSx)));
		    const {
		        name: componentName,
		        slot: componentSlot,
		        skipVariantsResolver: inputSkipVariantsResolver,
		        skipSx: inputSkipSx,
		        // TODO v6: remove `lowercaseFirstLetter()` in the next major release
		        // For more details: https://github.com/mui/material-ui/pull/37908
		        overridesResolver = defaultOverridesResolver(lowercaseFirstLetter(componentSlot))
		      } = inputOptions,
		      options = (0, _objectWithoutPropertiesLoose2.default)(inputOptions, _excluded3);

		    // if skipVariantsResolver option is defined, take the value, otherwise, true for root and false for other slots.
		    const skipVariantsResolver = inputSkipVariantsResolver !== undefined ? inputSkipVariantsResolver :
		    // TODO v6: remove `Root` in the next major release
		    // For more details: https://github.com/mui/material-ui/pull/37908
		    componentSlot && componentSlot !== 'Root' && componentSlot !== 'root' || false;
		    const skipSx = inputSkipSx || false;
		    let label;
		    let shouldForwardPropOption = shouldForwardProp;

		    // TODO v6: remove `Root` in the next major release
		    // For more details: https://github.com/mui/material-ui/pull/37908
		    if (componentSlot === 'Root' || componentSlot === 'root') {
		      shouldForwardPropOption = rootShouldForwardProp;
		    } else if (componentSlot) {
		      // any other slot specified
		      shouldForwardPropOption = slotShouldForwardProp;
		    } else if (isStringTag(tag)) {
		      // for string (html) tag, preserve the behavior in emotion & styled-components.
		      shouldForwardPropOption = undefined;
		    }
		    const defaultStyledResolver = (0, _styledEngine.default)(tag, (0, _extends2.default)({
		      shouldForwardProp: shouldForwardPropOption,
		      label
		    }, options));
		    const transformStyleArg = stylesArg => {
		      // On the server Emotion doesn't use React.forwardRef for creating components, so the created
		      // component stays as a function. This condition makes sure that we do not interpolate functions
		      // which are basically components used as a selectors.
		      if (typeof stylesArg === 'function' && stylesArg.__emotion_real !== stylesArg || (0, _deepmerge.isPlainObject)(stylesArg)) {
		        return props => processStyleArg(stylesArg, (0, _extends2.default)({}, props, {
		          theme: resolveTheme({
		            theme: props.theme,
		            defaultTheme,
		            themeId
		          })
		        }));
		      }
		      return stylesArg;
		    };
		    const muiStyledResolver = (styleArg, ...expressions) => {
		      let transformedStyleArg = transformStyleArg(styleArg);
		      const expressionsWithDefaultTheme = expressions ? expressions.map(transformStyleArg) : [];
		      if (componentName && overridesResolver) {
		        expressionsWithDefaultTheme.push(props => {
		          const theme = resolveTheme((0, _extends2.default)({}, props, {
		            defaultTheme,
		            themeId
		          }));
		          if (!theme.components || !theme.components[componentName] || !theme.components[componentName].styleOverrides) {
		            return null;
		          }
		          const styleOverrides = theme.components[componentName].styleOverrides;
		          const resolvedStyleOverrides = {};
		          // TODO: v7 remove iteration and use `resolveStyleArg(styleOverrides[slot])` directly
		          Object.entries(styleOverrides).forEach(([slotKey, slotStyle]) => {
		            resolvedStyleOverrides[slotKey] = processStyleArg(slotStyle, (0, _extends2.default)({}, props, {
		              theme
		            }));
		          });
		          return overridesResolver(props, resolvedStyleOverrides);
		        });
		      }
		      if (componentName && !skipVariantsResolver) {
		        expressionsWithDefaultTheme.push(props => {
		          var _theme$components;
		          const theme = resolveTheme((0, _extends2.default)({}, props, {
		            defaultTheme,
		            themeId
		          }));
		          const themeVariants = theme == null || (_theme$components = theme.components) == null || (_theme$components = _theme$components[componentName]) == null ? void 0 : _theme$components.variants;
		          return processStyleArg({
		            variants: themeVariants
		          }, (0, _extends2.default)({}, props, {
		            theme
		          }));
		        });
		      }
		      if (!skipSx) {
		        expressionsWithDefaultTheme.push(systemSx);
		      }
		      const numOfCustomFnsApplied = expressionsWithDefaultTheme.length - expressions.length;
		      if (Array.isArray(styleArg) && numOfCustomFnsApplied > 0) {
		        const placeholders = new Array(numOfCustomFnsApplied).fill('');
		        // If the type is array, than we need to add placeholders in the template for the overrides, variants and the sx styles.
		        transformedStyleArg = [...styleArg, ...placeholders];
		        transformedStyleArg.raw = [...styleArg.raw, ...placeholders];
		      }
		      const Component = defaultStyledResolver(transformedStyleArg, ...expressionsWithDefaultTheme);
		      if (tag.muiName) {
		        Component.muiName = tag.muiName;
		      }
		      return Component;
		    };
		    if (defaultStyledResolver.withConfig) {
		      muiStyledResolver.withConfig = defaultStyledResolver.withConfig;
		    }
		    return muiStyledResolver;
		  };
		}
		return createStyled$1;
	}

	var createStyledExports = /*@__PURE__*/ requireCreateStyled();
	var createStyled = /*@__PURE__*/getDefaultExportFromCjs(createStyledExports);

	// copied from @mui/system/createStyled
	function slotShouldForwardProp(prop) {
	  return prop !== 'ownerState' && prop !== 'theme' && prop !== 'sx' && prop !== 'as';
	}

	const rootShouldForwardProp = prop => slotShouldForwardProp(prop) && prop !== 'classes';
	var rootShouldForwardProp$1 = rootShouldForwardProp;

	const styled = createStyled({
	  themeId: THEME_ID,
	  defaultTheme: defaultTheme$1,
	  rootShouldForwardProp: rootShouldForwardProp$1
	});
	var styled$1 = styled;

	const _excluded$o = ["theme"];
	function ThemeProvider(_ref) {
	  let {
	      theme: themeInput
	    } = _ref,
	    props = _objectWithoutPropertiesLoose(_ref, _excluded$o);
	  const scopedTheme = themeInput[THEME_ID];
	  return /*#__PURE__*/jsxRuntimeExports.jsx(ThemeProvider$1, _extends$1({}, props, {
	    themeId: scopedTheme ? THEME_ID : undefined,
	    theme: scopedTheme || themeInput
	  }));
	}

	// Inspired by https://github.com/material-components/material-components-ios/blob/bca36107405594d5b7b16265a5b0ed698f85a5ee/components/Elevation/src/UIColor%2BMaterialElevation.m#L61
	const getOverlayAlpha = elevation => {
	  let alphaValue;
	  if (elevation < 1) {
	    alphaValue = 5.11916 * elevation ** 2;
	  } else {
	    alphaValue = 4.5 * Math.log(elevation + 1) + 2;
	  }
	  return (alphaValue / 100).toFixed(2);
	};
	var getOverlayAlpha$1 = getOverlayAlpha;

	var client = {};

	var reactDom = {exports: {}};

	var reactDom_production_min = {};

	var scheduler = {exports: {}};

	var scheduler_production_min = {};

	/**
	 * @license React
	 * scheduler.production.min.js
	 *
	 * Copyright (c) Facebook, Inc. and its affiliates.
	 *
	 * This source code is licensed under the MIT license found in the
	 * LICENSE file in the root directory of this source tree.
	 */

	var hasRequiredScheduler_production_min;

	function requireScheduler_production_min () {
		if (hasRequiredScheduler_production_min) return scheduler_production_min;
		hasRequiredScheduler_production_min = 1;
		(function (exports) {

			function f(a, b) {
			  var c = a.length;
			  a.push(b);
			  a: for (; 0 < c;) {
			    var d = c - 1 >>> 1,
			      e = a[d];
			    if (0 < g(e, b)) a[d] = b, a[c] = e, c = d;else break a;
			  }
			}
			function h(a) {
			  return 0 === a.length ? null : a[0];
			}
			function k(a) {
			  if (0 === a.length) return null;
			  var b = a[0],
			    c = a.pop();
			  if (c !== b) {
			    a[0] = c;
			    a: for (var d = 0, e = a.length, w = e >>> 1; d < w;) {
			      var m = 2 * (d + 1) - 1,
			        C = a[m],
			        n = m + 1,
			        x = a[n];
			      if (0 > g(C, c)) n < e && 0 > g(x, C) ? (a[d] = x, a[n] = c, d = n) : (a[d] = C, a[m] = c, d = m);else if (n < e && 0 > g(x, c)) a[d] = x, a[n] = c, d = n;else break a;
			    }
			  }
			  return b;
			}
			function g(a, b) {
			  var c = a.sortIndex - b.sortIndex;
			  return 0 !== c ? c : a.id - b.id;
			}
			if ("object" === typeof performance && "function" === typeof performance.now) {
			  var l = performance;
			  exports.unstable_now = function () {
			    return l.now();
			  };
			} else {
			  var p = Date,
			    q = p.now();
			  exports.unstable_now = function () {
			    return p.now() - q;
			  };
			}
			var r = [],
			  t = [],
			  u = 1,
			  v = null,
			  y = 3,
			  z = !1,
			  A = !1,
			  B = !1,
			  D = "function" === typeof setTimeout ? setTimeout : null,
			  E = "function" === typeof clearTimeout ? clearTimeout : null,
			  F = "undefined" !== typeof setImmediate ? setImmediate : null;
			"undefined" !== typeof navigator && void 0 !== navigator.scheduling && void 0 !== navigator.scheduling.isInputPending && navigator.scheduling.isInputPending.bind(navigator.scheduling);
			function G(a) {
			  for (var b = h(t); null !== b;) {
			    if (null === b.callback) k(t);else if (b.startTime <= a) k(t), b.sortIndex = b.expirationTime, f(r, b);else break;
			    b = h(t);
			  }
			}
			function H(a) {
			  B = !1;
			  G(a);
			  if (!A) if (null !== h(r)) A = !0, I(J);else {
			    var b = h(t);
			    null !== b && K(H, b.startTime - a);
			  }
			}
			function J(a, b) {
			  A = !1;
			  B && (B = !1, E(L), L = -1);
			  z = !0;
			  var c = y;
			  try {
			    G(b);
			    for (v = h(r); null !== v && (!(v.expirationTime > b) || a && !M());) {
			      var d = v.callback;
			      if ("function" === typeof d) {
			        v.callback = null;
			        y = v.priorityLevel;
			        var e = d(v.expirationTime <= b);
			        b = exports.unstable_now();
			        "function" === typeof e ? v.callback = e : v === h(r) && k(r);
			        G(b);
			      } else k(r);
			      v = h(r);
			    }
			    if (null !== v) var w = !0;else {
			      var m = h(t);
			      null !== m && K(H, m.startTime - b);
			      w = !1;
			    }
			    return w;
			  } finally {
			    v = null, y = c, z = !1;
			  }
			}
			var N = !1,
			  O = null,
			  L = -1,
			  P = 5,
			  Q = -1;
			function M() {
			  return exports.unstable_now() - Q < P ? !1 : !0;
			}
			function R() {
			  if (null !== O) {
			    var a = exports.unstable_now();
			    Q = a;
			    var b = !0;
			    try {
			      b = O(!0, a);
			    } finally {
			      b ? S() : (N = !1, O = null);
			    }
			  } else N = !1;
			}
			var S;
			if ("function" === typeof F) S = function () {
			  F(R);
			};else if ("undefined" !== typeof MessageChannel) {
			  var T = new MessageChannel(),
			    U = T.port2;
			  T.port1.onmessage = R;
			  S = function () {
			    U.postMessage(null);
			  };
			} else S = function () {
			  D(R, 0);
			};
			function I(a) {
			  O = a;
			  N || (N = !0, S());
			}
			function K(a, b) {
			  L = D(function () {
			    a(exports.unstable_now());
			  }, b);
			}
			exports.unstable_IdlePriority = 5;
			exports.unstable_ImmediatePriority = 1;
			exports.unstable_LowPriority = 4;
			exports.unstable_NormalPriority = 3;
			exports.unstable_Profiling = null;
			exports.unstable_UserBlockingPriority = 2;
			exports.unstable_cancelCallback = function (a) {
			  a.callback = null;
			};
			exports.unstable_continueExecution = function () {
			  A || z || (A = !0, I(J));
			};
			exports.unstable_forceFrameRate = function (a) {
			  0 > a || 125 < a ? console.error("forceFrameRate takes a positive int between 0 and 125, forcing frame rates higher than 125 fps is not supported") : P = 0 < a ? Math.floor(1E3 / a) : 5;
			};
			exports.unstable_getCurrentPriorityLevel = function () {
			  return y;
			};
			exports.unstable_getFirstCallbackNode = function () {
			  return h(r);
			};
			exports.unstable_next = function (a) {
			  switch (y) {
			    case 1:
			    case 2:
			    case 3:
			      var b = 3;
			      break;
			    default:
			      b = y;
			  }
			  var c = y;
			  y = b;
			  try {
			    return a();
			  } finally {
			    y = c;
			  }
			};
			exports.unstable_pauseExecution = function () {};
			exports.unstable_requestPaint = function () {};
			exports.unstable_runWithPriority = function (a, b) {
			  switch (a) {
			    case 1:
			    case 2:
			    case 3:
			    case 4:
			    case 5:
			      break;
			    default:
			      a = 3;
			  }
			  var c = y;
			  y = a;
			  try {
			    return b();
			  } finally {
			    y = c;
			  }
			};
			exports.unstable_scheduleCallback = function (a, b, c) {
			  var d = exports.unstable_now();
			  "object" === typeof c && null !== c ? (c = c.delay, c = "number" === typeof c && 0 < c ? d + c : d) : c = d;
			  switch (a) {
			    case 1:
			      var e = -1;
			      break;
			    case 2:
			      e = 250;
			      break;
			    case 5:
			      e = 1073741823;
			      break;
			    case 4:
			      e = 1E4;
			      break;
			    default:
			      e = 5E3;
			  }
			  e = c + e;
			  a = {
			    id: u++,
			    callback: b,
			    priorityLevel: a,
			    startTime: c,
			    expirationTime: e,
			    sortIndex: -1
			  };
			  c > d ? (a.sortIndex = c, f(t, a), null === h(r) && a === h(t) && (B ? (E(L), L = -1) : B = !0, K(H, c - d))) : (a.sortIndex = e, f(r, a), A || z || (A = !0, I(J)));
			  return a;
			};
			exports.unstable_shouldYield = M;
			exports.unstable_wrapCallback = function (a) {
			  var b = y;
			  return function () {
			    var c = y;
			    y = b;
			    try {
			      return a.apply(this, arguments);
			    } finally {
			      y = c;
			    }
			  };
			}; 
		} (scheduler_production_min));
		return scheduler_production_min;
	}

	var hasRequiredScheduler;

	function requireScheduler () {
		if (hasRequiredScheduler) return scheduler.exports;
		hasRequiredScheduler = 1;

		{
		  scheduler.exports = requireScheduler_production_min();
		}
		return scheduler.exports;
	}

	/**
	 * @license React
	 * react-dom.production.min.js
	 *
	 * Copyright (c) Facebook, Inc. and its affiliates.
	 *
	 * This source code is licensed under the MIT license found in the
	 * LICENSE file in the root directory of this source tree.
	 */

	var hasRequiredReactDom_production_min;

	function requireReactDom_production_min () {
		if (hasRequiredReactDom_production_min) return reactDom_production_min;
		hasRequiredReactDom_production_min = 1;

		var aa = requireReact(),
		  ca = requireScheduler();
		function p(a) {
		  for (var b = "https://reactjs.org/docs/error-decoder.html?invariant=" + a, c = 1; c < arguments.length; c++) b += "&args[]=" + encodeURIComponent(arguments[c]);
		  return "Minified React error #" + a + "; visit " + b + " for the full message or use the non-minified dev environment for full errors and additional helpful warnings.";
		}
		var da = new Set(),
		  ea = {};
		function fa(a, b) {
		  ha(a, b);
		  ha(a + "Capture", b);
		}
		function ha(a, b) {
		  ea[a] = b;
		  for (a = 0; a < b.length; a++) da.add(b[a]);
		}
		var ia = !("undefined" === typeof window || "undefined" === typeof window.document || "undefined" === typeof window.document.createElement),
		  ja = Object.prototype.hasOwnProperty,
		  ka = /^[:A-Z_a-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD][:A-Z_a-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD\-.0-9\u00B7\u0300-\u036F\u203F-\u2040]*$/,
		  la = {},
		  ma = {};
		function oa(a) {
		  if (ja.call(ma, a)) return !0;
		  if (ja.call(la, a)) return !1;
		  if (ka.test(a)) return ma[a] = !0;
		  la[a] = !0;
		  return !1;
		}
		function pa(a, b, c, d) {
		  if (null !== c && 0 === c.type) return !1;
		  switch (typeof b) {
		    case "function":
		    case "symbol":
		      return !0;
		    case "boolean":
		      if (d) return !1;
		      if (null !== c) return !c.acceptsBooleans;
		      a = a.toLowerCase().slice(0, 5);
		      return "data-" !== a && "aria-" !== a;
		    default:
		      return !1;
		  }
		}
		function qa(a, b, c, d) {
		  if (null === b || "undefined" === typeof b || pa(a, b, c, d)) return !0;
		  if (d) return !1;
		  if (null !== c) switch (c.type) {
		    case 3:
		      return !b;
		    case 4:
		      return !1 === b;
		    case 5:
		      return isNaN(b);
		    case 6:
		      return isNaN(b) || 1 > b;
		  }
		  return !1;
		}
		function v(a, b, c, d, e, f, g) {
		  this.acceptsBooleans = 2 === b || 3 === b || 4 === b;
		  this.attributeName = d;
		  this.attributeNamespace = e;
		  this.mustUseProperty = c;
		  this.propertyName = a;
		  this.type = b;
		  this.sanitizeURL = f;
		  this.removeEmptyString = g;
		}
		var z = {};
		"children dangerouslySetInnerHTML defaultValue defaultChecked innerHTML suppressContentEditableWarning suppressHydrationWarning style".split(" ").forEach(function (a) {
		  z[a] = new v(a, 0, !1, a, null, !1, !1);
		});
		[["acceptCharset", "accept-charset"], ["className", "class"], ["htmlFor", "for"], ["httpEquiv", "http-equiv"]].forEach(function (a) {
		  var b = a[0];
		  z[b] = new v(b, 1, !1, a[1], null, !1, !1);
		});
		["contentEditable", "draggable", "spellCheck", "value"].forEach(function (a) {
		  z[a] = new v(a, 2, !1, a.toLowerCase(), null, !1, !1);
		});
		["autoReverse", "externalResourcesRequired", "focusable", "preserveAlpha"].forEach(function (a) {
		  z[a] = new v(a, 2, !1, a, null, !1, !1);
		});
		"allowFullScreen async autoFocus autoPlay controls default defer disabled disablePictureInPicture disableRemotePlayback formNoValidate hidden loop noModule noValidate open playsInline readOnly required reversed scoped seamless itemScope".split(" ").forEach(function (a) {
		  z[a] = new v(a, 3, !1, a.toLowerCase(), null, !1, !1);
		});
		["checked", "multiple", "muted", "selected"].forEach(function (a) {
		  z[a] = new v(a, 3, !0, a, null, !1, !1);
		});
		["capture", "download"].forEach(function (a) {
		  z[a] = new v(a, 4, !1, a, null, !1, !1);
		});
		["cols", "rows", "size", "span"].forEach(function (a) {
		  z[a] = new v(a, 6, !1, a, null, !1, !1);
		});
		["rowSpan", "start"].forEach(function (a) {
		  z[a] = new v(a, 5, !1, a.toLowerCase(), null, !1, !1);
		});
		var ra = /[\-:]([a-z])/g;
		function sa(a) {
		  return a[1].toUpperCase();
		}
		"accent-height alignment-baseline arabic-form baseline-shift cap-height clip-path clip-rule color-interpolation color-interpolation-filters color-profile color-rendering dominant-baseline enable-background fill-opacity fill-rule flood-color flood-opacity font-family font-size font-size-adjust font-stretch font-style font-variant font-weight glyph-name glyph-orientation-horizontal glyph-orientation-vertical horiz-adv-x horiz-origin-x image-rendering letter-spacing lighting-color marker-end marker-mid marker-start overline-position overline-thickness paint-order panose-1 pointer-events rendering-intent shape-rendering stop-color stop-opacity strikethrough-position strikethrough-thickness stroke-dasharray stroke-dashoffset stroke-linecap stroke-linejoin stroke-miterlimit stroke-opacity stroke-width text-anchor text-decoration text-rendering underline-position underline-thickness unicode-bidi unicode-range units-per-em v-alphabetic v-hanging v-ideographic v-mathematical vector-effect vert-adv-y vert-origin-x vert-origin-y word-spacing writing-mode xmlns:xlink x-height".split(" ").forEach(function (a) {
		  var b = a.replace(ra, sa);
		  z[b] = new v(b, 1, !1, a, null, !1, !1);
		});
		"xlink:actuate xlink:arcrole xlink:role xlink:show xlink:title xlink:type".split(" ").forEach(function (a) {
		  var b = a.replace(ra, sa);
		  z[b] = new v(b, 1, !1, a, "http://www.w3.org/1999/xlink", !1, !1);
		});
		["xml:base", "xml:lang", "xml:space"].forEach(function (a) {
		  var b = a.replace(ra, sa);
		  z[b] = new v(b, 1, !1, a, "http://www.w3.org/XML/1998/namespace", !1, !1);
		});
		["tabIndex", "crossOrigin"].forEach(function (a) {
		  z[a] = new v(a, 1, !1, a.toLowerCase(), null, !1, !1);
		});
		z.xlinkHref = new v("xlinkHref", 1, !1, "xlink:href", "http://www.w3.org/1999/xlink", !0, !1);
		["src", "href", "action", "formAction"].forEach(function (a) {
		  z[a] = new v(a, 1, !1, a.toLowerCase(), null, !0, !0);
		});
		function ta(a, b, c, d) {
		  var e = z.hasOwnProperty(b) ? z[b] : null;
		  if (null !== e ? 0 !== e.type : d || !(2 < b.length) || "o" !== b[0] && "O" !== b[0] || "n" !== b[1] && "N" !== b[1]) qa(b, c, e, d) && (c = null), d || null === e ? oa(b) && (null === c ? a.removeAttribute(b) : a.setAttribute(b, "" + c)) : e.mustUseProperty ? a[e.propertyName] = null === c ? 3 === e.type ? !1 : "" : c : (b = e.attributeName, d = e.attributeNamespace, null === c ? a.removeAttribute(b) : (e = e.type, c = 3 === e || 4 === e && !0 === c ? "" : "" + c, d ? a.setAttributeNS(d, b, c) : a.setAttribute(b, c)));
		}
		var ua = aa.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED,
		  va = Symbol.for("react.element"),
		  wa = Symbol.for("react.portal"),
		  ya = Symbol.for("react.fragment"),
		  za = Symbol.for("react.strict_mode"),
		  Aa = Symbol.for("react.profiler"),
		  Ba = Symbol.for("react.provider"),
		  Ca = Symbol.for("react.context"),
		  Da = Symbol.for("react.forward_ref"),
		  Ea = Symbol.for("react.suspense"),
		  Fa = Symbol.for("react.suspense_list"),
		  Ga = Symbol.for("react.memo"),
		  Ha = Symbol.for("react.lazy");
		var Ia = Symbol.for("react.offscreen");
		var Ja = Symbol.iterator;
		function Ka(a) {
		  if (null === a || "object" !== typeof a) return null;
		  a = Ja && a[Ja] || a["@@iterator"];
		  return "function" === typeof a ? a : null;
		}
		var A = Object.assign,
		  La;
		function Ma(a) {
		  if (void 0 === La) try {
		    throw Error();
		  } catch (c) {
		    var b = c.stack.trim().match(/\n( *(at )?)/);
		    La = b && b[1] || "";
		  }
		  return "\n" + La + a;
		}
		var Na = !1;
		function Oa(a, b) {
		  if (!a || Na) return "";
		  Na = !0;
		  var c = Error.prepareStackTrace;
		  Error.prepareStackTrace = void 0;
		  try {
		    if (b) {
		      if (b = function () {
		        throw Error();
		      }, Object.defineProperty(b.prototype, "props", {
		        set: function () {
		          throw Error();
		        }
		      }), "object" === typeof Reflect && Reflect.construct) {
		        try {
		          Reflect.construct(b, []);
		        } catch (l) {
		          var d = l;
		        }
		        Reflect.construct(a, [], b);
		      } else {
		        try {
		          b.call();
		        } catch (l) {
		          d = l;
		        }
		        a.call(b.prototype);
		      }
		    } else {
		      try {
		        throw Error();
		      } catch (l) {
		        d = l;
		      }
		      a();
		    }
		  } catch (l) {
		    if (l && d && "string" === typeof l.stack) {
		      for (var e = l.stack.split("\n"), f = d.stack.split("\n"), g = e.length - 1, h = f.length - 1; 1 <= g && 0 <= h && e[g] !== f[h];) h--;
		      for (; 1 <= g && 0 <= h; g--, h--) if (e[g] !== f[h]) {
		        if (1 !== g || 1 !== h) {
		          do if (g--, h--, 0 > h || e[g] !== f[h]) {
		            var k = "\n" + e[g].replace(" at new ", " at ");
		            a.displayName && k.includes("<anonymous>") && (k = k.replace("<anonymous>", a.displayName));
		            return k;
		          } while (1 <= g && 0 <= h);
		        }
		        break;
		      }
		    }
		  } finally {
		    Na = !1, Error.prepareStackTrace = c;
		  }
		  return (a = a ? a.displayName || a.name : "") ? Ma(a) : "";
		}
		function Pa(a) {
		  switch (a.tag) {
		    case 5:
		      return Ma(a.type);
		    case 16:
		      return Ma("Lazy");
		    case 13:
		      return Ma("Suspense");
		    case 19:
		      return Ma("SuspenseList");
		    case 0:
		    case 2:
		    case 15:
		      return a = Oa(a.type, !1), a;
		    case 11:
		      return a = Oa(a.type.render, !1), a;
		    case 1:
		      return a = Oa(a.type, !0), a;
		    default:
		      return "";
		  }
		}
		function Qa(a) {
		  if (null == a) return null;
		  if ("function" === typeof a) return a.displayName || a.name || null;
		  if ("string" === typeof a) return a;
		  switch (a) {
		    case ya:
		      return "Fragment";
		    case wa:
		      return "Portal";
		    case Aa:
		      return "Profiler";
		    case za:
		      return "StrictMode";
		    case Ea:
		      return "Suspense";
		    case Fa:
		      return "SuspenseList";
		  }
		  if ("object" === typeof a) switch (a.$$typeof) {
		    case Ca:
		      return (a.displayName || "Context") + ".Consumer";
		    case Ba:
		      return (a._context.displayName || "Context") + ".Provider";
		    case Da:
		      var b = a.render;
		      a = a.displayName;
		      a || (a = b.displayName || b.name || "", a = "" !== a ? "ForwardRef(" + a + ")" : "ForwardRef");
		      return a;
		    case Ga:
		      return b = a.displayName || null, null !== b ? b : Qa(a.type) || "Memo";
		    case Ha:
		      b = a._payload;
		      a = a._init;
		      try {
		        return Qa(a(b));
		      } catch (c) {}
		  }
		  return null;
		}
		function Ra(a) {
		  var b = a.type;
		  switch (a.tag) {
		    case 24:
		      return "Cache";
		    case 9:
		      return (b.displayName || "Context") + ".Consumer";
		    case 10:
		      return (b._context.displayName || "Context") + ".Provider";
		    case 18:
		      return "DehydratedFragment";
		    case 11:
		      return a = b.render, a = a.displayName || a.name || "", b.displayName || ("" !== a ? "ForwardRef(" + a + ")" : "ForwardRef");
		    case 7:
		      return "Fragment";
		    case 5:
		      return b;
		    case 4:
		      return "Portal";
		    case 3:
		      return "Root";
		    case 6:
		      return "Text";
		    case 16:
		      return Qa(b);
		    case 8:
		      return b === za ? "StrictMode" : "Mode";
		    case 22:
		      return "Offscreen";
		    case 12:
		      return "Profiler";
		    case 21:
		      return "Scope";
		    case 13:
		      return "Suspense";
		    case 19:
		      return "SuspenseList";
		    case 25:
		      return "TracingMarker";
		    case 1:
		    case 0:
		    case 17:
		    case 2:
		    case 14:
		    case 15:
		      if ("function" === typeof b) return b.displayName || b.name || null;
		      if ("string" === typeof b) return b;
		  }
		  return null;
		}
		function Sa(a) {
		  switch (typeof a) {
		    case "boolean":
		    case "number":
		    case "string":
		    case "undefined":
		      return a;
		    case "object":
		      return a;
		    default:
		      return "";
		  }
		}
		function Ta(a) {
		  var b = a.type;
		  return (a = a.nodeName) && "input" === a.toLowerCase() && ("checkbox" === b || "radio" === b);
		}
		function Ua(a) {
		  var b = Ta(a) ? "checked" : "value",
		    c = Object.getOwnPropertyDescriptor(a.constructor.prototype, b),
		    d = "" + a[b];
		  if (!a.hasOwnProperty(b) && "undefined" !== typeof c && "function" === typeof c.get && "function" === typeof c.set) {
		    var e = c.get,
		      f = c.set;
		    Object.defineProperty(a, b, {
		      configurable: !0,
		      get: function () {
		        return e.call(this);
		      },
		      set: function (a) {
		        d = "" + a;
		        f.call(this, a);
		      }
		    });
		    Object.defineProperty(a, b, {
		      enumerable: c.enumerable
		    });
		    return {
		      getValue: function () {
		        return d;
		      },
		      setValue: function (a) {
		        d = "" + a;
		      },
		      stopTracking: function () {
		        a._valueTracker = null;
		        delete a[b];
		      }
		    };
		  }
		}
		function Va(a) {
		  a._valueTracker || (a._valueTracker = Ua(a));
		}
		function Wa(a) {
		  if (!a) return !1;
		  var b = a._valueTracker;
		  if (!b) return !0;
		  var c = b.getValue();
		  var d = "";
		  a && (d = Ta(a) ? a.checked ? "true" : "false" : a.value);
		  a = d;
		  return a !== c ? (b.setValue(a), !0) : !1;
		}
		function Xa(a) {
		  a = a || ("undefined" !== typeof document ? document : void 0);
		  if ("undefined" === typeof a) return null;
		  try {
		    return a.activeElement || a.body;
		  } catch (b) {
		    return a.body;
		  }
		}
		function Ya(a, b) {
		  var c = b.checked;
		  return A({}, b, {
		    defaultChecked: void 0,
		    defaultValue: void 0,
		    value: void 0,
		    checked: null != c ? c : a._wrapperState.initialChecked
		  });
		}
		function Za(a, b) {
		  var c = null == b.defaultValue ? "" : b.defaultValue,
		    d = null != b.checked ? b.checked : b.defaultChecked;
		  c = Sa(null != b.value ? b.value : c);
		  a._wrapperState = {
		    initialChecked: d,
		    initialValue: c,
		    controlled: "checkbox" === b.type || "radio" === b.type ? null != b.checked : null != b.value
		  };
		}
		function ab(a, b) {
		  b = b.checked;
		  null != b && ta(a, "checked", b, !1);
		}
		function bb(a, b) {
		  ab(a, b);
		  var c = Sa(b.value),
		    d = b.type;
		  if (null != c) {
		    if ("number" === d) {
		      if (0 === c && "" === a.value || a.value != c) a.value = "" + c;
		    } else a.value !== "" + c && (a.value = "" + c);
		  } else if ("submit" === d || "reset" === d) {
		    a.removeAttribute("value");
		    return;
		  }
		  b.hasOwnProperty("value") ? cb(a, b.type, c) : b.hasOwnProperty("defaultValue") && cb(a, b.type, Sa(b.defaultValue));
		  null == b.checked && null != b.defaultChecked && (a.defaultChecked = !!b.defaultChecked);
		}
		function db(a, b, c) {
		  if (b.hasOwnProperty("value") || b.hasOwnProperty("defaultValue")) {
		    var d = b.type;
		    if (!("submit" !== d && "reset" !== d || void 0 !== b.value && null !== b.value)) return;
		    b = "" + a._wrapperState.initialValue;
		    c || b === a.value || (a.value = b);
		    a.defaultValue = b;
		  }
		  c = a.name;
		  "" !== c && (a.name = "");
		  a.defaultChecked = !!a._wrapperState.initialChecked;
		  "" !== c && (a.name = c);
		}
		function cb(a, b, c) {
		  if ("number" !== b || Xa(a.ownerDocument) !== a) null == c ? a.defaultValue = "" + a._wrapperState.initialValue : a.defaultValue !== "" + c && (a.defaultValue = "" + c);
		}
		var eb = Array.isArray;
		function fb(a, b, c, d) {
		  a = a.options;
		  if (b) {
		    b = {};
		    for (var e = 0; e < c.length; e++) b["$" + c[e]] = !0;
		    for (c = 0; c < a.length; c++) e = b.hasOwnProperty("$" + a[c].value), a[c].selected !== e && (a[c].selected = e), e && d && (a[c].defaultSelected = !0);
		  } else {
		    c = "" + Sa(c);
		    b = null;
		    for (e = 0; e < a.length; e++) {
		      if (a[e].value === c) {
		        a[e].selected = !0;
		        d && (a[e].defaultSelected = !0);
		        return;
		      }
		      null !== b || a[e].disabled || (b = a[e]);
		    }
		    null !== b && (b.selected = !0);
		  }
		}
		function gb(a, b) {
		  if (null != b.dangerouslySetInnerHTML) throw Error(p(91));
		  return A({}, b, {
		    value: void 0,
		    defaultValue: void 0,
		    children: "" + a._wrapperState.initialValue
		  });
		}
		function hb(a, b) {
		  var c = b.value;
		  if (null == c) {
		    c = b.children;
		    b = b.defaultValue;
		    if (null != c) {
		      if (null != b) throw Error(p(92));
		      if (eb(c)) {
		        if (1 < c.length) throw Error(p(93));
		        c = c[0];
		      }
		      b = c;
		    }
		    null == b && (b = "");
		    c = b;
		  }
		  a._wrapperState = {
		    initialValue: Sa(c)
		  };
		}
		function ib(a, b) {
		  var c = Sa(b.value),
		    d = Sa(b.defaultValue);
		  null != c && (c = "" + c, c !== a.value && (a.value = c), null == b.defaultValue && a.defaultValue !== c && (a.defaultValue = c));
		  null != d && (a.defaultValue = "" + d);
		}
		function jb(a) {
		  var b = a.textContent;
		  b === a._wrapperState.initialValue && "" !== b && null !== b && (a.value = b);
		}
		function kb(a) {
		  switch (a) {
		    case "svg":
		      return "http://www.w3.org/2000/svg";
		    case "math":
		      return "http://www.w3.org/1998/Math/MathML";
		    default:
		      return "http://www.w3.org/1999/xhtml";
		  }
		}
		function lb(a, b) {
		  return null == a || "http://www.w3.org/1999/xhtml" === a ? kb(b) : "http://www.w3.org/2000/svg" === a && "foreignObject" === b ? "http://www.w3.org/1999/xhtml" : a;
		}
		var mb,
		  nb = function (a) {
		    return "undefined" !== typeof MSApp && MSApp.execUnsafeLocalFunction ? function (b, c, d, e) {
		      MSApp.execUnsafeLocalFunction(function () {
		        return a(b, c, d, e);
		      });
		    } : a;
		  }(function (a, b) {
		    if ("http://www.w3.org/2000/svg" !== a.namespaceURI || "innerHTML" in a) a.innerHTML = b;else {
		      mb = mb || document.createElement("div");
		      mb.innerHTML = "<svg>" + b.valueOf().toString() + "</svg>";
		      for (b = mb.firstChild; a.firstChild;) a.removeChild(a.firstChild);
		      for (; b.firstChild;) a.appendChild(b.firstChild);
		    }
		  });
		function ob(a, b) {
		  if (b) {
		    var c = a.firstChild;
		    if (c && c === a.lastChild && 3 === c.nodeType) {
		      c.nodeValue = b;
		      return;
		    }
		  }
		  a.textContent = b;
		}
		var pb = {
		    animationIterationCount: !0,
		    aspectRatio: !0,
		    borderImageOutset: !0,
		    borderImageSlice: !0,
		    borderImageWidth: !0,
		    boxFlex: !0,
		    boxFlexGroup: !0,
		    boxOrdinalGroup: !0,
		    columnCount: !0,
		    columns: !0,
		    flex: !0,
		    flexGrow: !0,
		    flexPositive: !0,
		    flexShrink: !0,
		    flexNegative: !0,
		    flexOrder: !0,
		    gridArea: !0,
		    gridRow: !0,
		    gridRowEnd: !0,
		    gridRowSpan: !0,
		    gridRowStart: !0,
		    gridColumn: !0,
		    gridColumnEnd: !0,
		    gridColumnSpan: !0,
		    gridColumnStart: !0,
		    fontWeight: !0,
		    lineClamp: !0,
		    lineHeight: !0,
		    opacity: !0,
		    order: !0,
		    orphans: !0,
		    tabSize: !0,
		    widows: !0,
		    zIndex: !0,
		    zoom: !0,
		    fillOpacity: !0,
		    floodOpacity: !0,
		    stopOpacity: !0,
		    strokeDasharray: !0,
		    strokeDashoffset: !0,
		    strokeMiterlimit: !0,
		    strokeOpacity: !0,
		    strokeWidth: !0
		  },
		  qb = ["Webkit", "ms", "Moz", "O"];
		Object.keys(pb).forEach(function (a) {
		  qb.forEach(function (b) {
		    b = b + a.charAt(0).toUpperCase() + a.substring(1);
		    pb[b] = pb[a];
		  });
		});
		function rb(a, b, c) {
		  return null == b || "boolean" === typeof b || "" === b ? "" : c || "number" !== typeof b || 0 === b || pb.hasOwnProperty(a) && pb[a] ? ("" + b).trim() : b + "px";
		}
		function sb(a, b) {
		  a = a.style;
		  for (var c in b) if (b.hasOwnProperty(c)) {
		    var d = 0 === c.indexOf("--"),
		      e = rb(c, b[c], d);
		    "float" === c && (c = "cssFloat");
		    d ? a.setProperty(c, e) : a[c] = e;
		  }
		}
		var tb = A({
		  menuitem: !0
		}, {
		  area: !0,
		  base: !0,
		  br: !0,
		  col: !0,
		  embed: !0,
		  hr: !0,
		  img: !0,
		  input: !0,
		  keygen: !0,
		  link: !0,
		  meta: !0,
		  param: !0,
		  source: !0,
		  track: !0,
		  wbr: !0
		});
		function ub(a, b) {
		  if (b) {
		    if (tb[a] && (null != b.children || null != b.dangerouslySetInnerHTML)) throw Error(p(137, a));
		    if (null != b.dangerouslySetInnerHTML) {
		      if (null != b.children) throw Error(p(60));
		      if ("object" !== typeof b.dangerouslySetInnerHTML || !("__html" in b.dangerouslySetInnerHTML)) throw Error(p(61));
		    }
		    if (null != b.style && "object" !== typeof b.style) throw Error(p(62));
		  }
		}
		function vb(a, b) {
		  if (-1 === a.indexOf("-")) return "string" === typeof b.is;
		  switch (a) {
		    case "annotation-xml":
		    case "color-profile":
		    case "font-face":
		    case "font-face-src":
		    case "font-face-uri":
		    case "font-face-format":
		    case "font-face-name":
		    case "missing-glyph":
		      return !1;
		    default:
		      return !0;
		  }
		}
		var wb = null;
		function xb(a) {
		  a = a.target || a.srcElement || window;
		  a.correspondingUseElement && (a = a.correspondingUseElement);
		  return 3 === a.nodeType ? a.parentNode : a;
		}
		var yb = null,
		  zb = null,
		  Ab = null;
		function Bb(a) {
		  if (a = Cb(a)) {
		    if ("function" !== typeof yb) throw Error(p(280));
		    var b = a.stateNode;
		    b && (b = Db(b), yb(a.stateNode, a.type, b));
		  }
		}
		function Eb(a) {
		  zb ? Ab ? Ab.push(a) : Ab = [a] : zb = a;
		}
		function Fb() {
		  if (zb) {
		    var a = zb,
		      b = Ab;
		    Ab = zb = null;
		    Bb(a);
		    if (b) for (a = 0; a < b.length; a++) Bb(b[a]);
		  }
		}
		function Gb(a, b) {
		  return a(b);
		}
		function Hb() {}
		var Ib = !1;
		function Jb(a, b, c) {
		  if (Ib) return a(b, c);
		  Ib = !0;
		  try {
		    return Gb(a, b, c);
		  } finally {
		    if (Ib = !1, null !== zb || null !== Ab) Hb(), Fb();
		  }
		}
		function Kb(a, b) {
		  var c = a.stateNode;
		  if (null === c) return null;
		  var d = Db(c);
		  if (null === d) return null;
		  c = d[b];
		  a: switch (b) {
		    case "onClick":
		    case "onClickCapture":
		    case "onDoubleClick":
		    case "onDoubleClickCapture":
		    case "onMouseDown":
		    case "onMouseDownCapture":
		    case "onMouseMove":
		    case "onMouseMoveCapture":
		    case "onMouseUp":
		    case "onMouseUpCapture":
		    case "onMouseEnter":
		      (d = !d.disabled) || (a = a.type, d = !("button" === a || "input" === a || "select" === a || "textarea" === a));
		      a = !d;
		      break a;
		    default:
		      a = !1;
		  }
		  if (a) return null;
		  if (c && "function" !== typeof c) throw Error(p(231, b, typeof c));
		  return c;
		}
		var Lb = !1;
		if (ia) try {
		  var Mb = {};
		  Object.defineProperty(Mb, "passive", {
		    get: function () {
		      Lb = !0;
		    }
		  });
		  window.addEventListener("test", Mb, Mb);
		  window.removeEventListener("test", Mb, Mb);
		} catch (a) {
		  Lb = !1;
		}
		function Nb(a, b, c, d, e, f, g, h, k) {
		  var l = Array.prototype.slice.call(arguments, 3);
		  try {
		    b.apply(c, l);
		  } catch (m) {
		    this.onError(m);
		  }
		}
		var Ob = !1,
		  Pb = null,
		  Qb = !1,
		  Rb = null,
		  Sb = {
		    onError: function (a) {
		      Ob = !0;
		      Pb = a;
		    }
		  };
		function Tb(a, b, c, d, e, f, g, h, k) {
		  Ob = !1;
		  Pb = null;
		  Nb.apply(Sb, arguments);
		}
		function Ub(a, b, c, d, e, f, g, h, k) {
		  Tb.apply(this, arguments);
		  if (Ob) {
		    if (Ob) {
		      var l = Pb;
		      Ob = !1;
		      Pb = null;
		    } else throw Error(p(198));
		    Qb || (Qb = !0, Rb = l);
		  }
		}
		function Vb(a) {
		  var b = a,
		    c = a;
		  if (a.alternate) for (; b.return;) b = b.return;else {
		    a = b;
		    do b = a, 0 !== (b.flags & 4098) && (c = b.return), a = b.return; while (a);
		  }
		  return 3 === b.tag ? c : null;
		}
		function Wb(a) {
		  if (13 === a.tag) {
		    var b = a.memoizedState;
		    null === b && (a = a.alternate, null !== a && (b = a.memoizedState));
		    if (null !== b) return b.dehydrated;
		  }
		  return null;
		}
		function Xb(a) {
		  if (Vb(a) !== a) throw Error(p(188));
		}
		function Yb(a) {
		  var b = a.alternate;
		  if (!b) {
		    b = Vb(a);
		    if (null === b) throw Error(p(188));
		    return b !== a ? null : a;
		  }
		  for (var c = a, d = b;;) {
		    var e = c.return;
		    if (null === e) break;
		    var f = e.alternate;
		    if (null === f) {
		      d = e.return;
		      if (null !== d) {
		        c = d;
		        continue;
		      }
		      break;
		    }
		    if (e.child === f.child) {
		      for (f = e.child; f;) {
		        if (f === c) return Xb(e), a;
		        if (f === d) return Xb(e), b;
		        f = f.sibling;
		      }
		      throw Error(p(188));
		    }
		    if (c.return !== d.return) c = e, d = f;else {
		      for (var g = !1, h = e.child; h;) {
		        if (h === c) {
		          g = !0;
		          c = e;
		          d = f;
		          break;
		        }
		        if (h === d) {
		          g = !0;
		          d = e;
		          c = f;
		          break;
		        }
		        h = h.sibling;
		      }
		      if (!g) {
		        for (h = f.child; h;) {
		          if (h === c) {
		            g = !0;
		            c = f;
		            d = e;
		            break;
		          }
		          if (h === d) {
		            g = !0;
		            d = f;
		            c = e;
		            break;
		          }
		          h = h.sibling;
		        }
		        if (!g) throw Error(p(189));
		      }
		    }
		    if (c.alternate !== d) throw Error(p(190));
		  }
		  if (3 !== c.tag) throw Error(p(188));
		  return c.stateNode.current === c ? a : b;
		}
		function Zb(a) {
		  a = Yb(a);
		  return null !== a ? $b(a) : null;
		}
		function $b(a) {
		  if (5 === a.tag || 6 === a.tag) return a;
		  for (a = a.child; null !== a;) {
		    var b = $b(a);
		    if (null !== b) return b;
		    a = a.sibling;
		  }
		  return null;
		}
		var ac = ca.unstable_scheduleCallback,
		  bc = ca.unstable_cancelCallback,
		  cc = ca.unstable_shouldYield,
		  dc = ca.unstable_requestPaint,
		  B = ca.unstable_now,
		  ec = ca.unstable_getCurrentPriorityLevel,
		  fc = ca.unstable_ImmediatePriority,
		  gc = ca.unstable_UserBlockingPriority,
		  hc = ca.unstable_NormalPriority,
		  ic = ca.unstable_LowPriority,
		  jc = ca.unstable_IdlePriority,
		  kc = null,
		  lc = null;
		function mc(a) {
		  if (lc && "function" === typeof lc.onCommitFiberRoot) try {
		    lc.onCommitFiberRoot(kc, a, void 0, 128 === (a.current.flags & 128));
		  } catch (b) {}
		}
		var oc = Math.clz32 ? Math.clz32 : nc,
		  pc = Math.log,
		  qc = Math.LN2;
		function nc(a) {
		  a >>>= 0;
		  return 0 === a ? 32 : 31 - (pc(a) / qc | 0) | 0;
		}
		var rc = 64,
		  sc = 4194304;
		function tc(a) {
		  switch (a & -a) {
		    case 1:
		      return 1;
		    case 2:
		      return 2;
		    case 4:
		      return 4;
		    case 8:
		      return 8;
		    case 16:
		      return 16;
		    case 32:
		      return 32;
		    case 64:
		    case 128:
		    case 256:
		    case 512:
		    case 1024:
		    case 2048:
		    case 4096:
		    case 8192:
		    case 16384:
		    case 32768:
		    case 65536:
		    case 131072:
		    case 262144:
		    case 524288:
		    case 1048576:
		    case 2097152:
		      return a & 4194240;
		    case 4194304:
		    case 8388608:
		    case 16777216:
		    case 33554432:
		    case 67108864:
		      return a & 130023424;
		    case 134217728:
		      return 134217728;
		    case 268435456:
		      return 268435456;
		    case 536870912:
		      return 536870912;
		    case 1073741824:
		      return 1073741824;
		    default:
		      return a;
		  }
		}
		function uc(a, b) {
		  var c = a.pendingLanes;
		  if (0 === c) return 0;
		  var d = 0,
		    e = a.suspendedLanes,
		    f = a.pingedLanes,
		    g = c & 268435455;
		  if (0 !== g) {
		    var h = g & ~e;
		    0 !== h ? d = tc(h) : (f &= g, 0 !== f && (d = tc(f)));
		  } else g = c & ~e, 0 !== g ? d = tc(g) : 0 !== f && (d = tc(f));
		  if (0 === d) return 0;
		  if (0 !== b && b !== d && 0 === (b & e) && (e = d & -d, f = b & -b, e >= f || 16 === e && 0 !== (f & 4194240))) return b;
		  0 !== (d & 4) && (d |= c & 16);
		  b = a.entangledLanes;
		  if (0 !== b) for (a = a.entanglements, b &= d; 0 < b;) c = 31 - oc(b), e = 1 << c, d |= a[c], b &= ~e;
		  return d;
		}
		function vc(a, b) {
		  switch (a) {
		    case 1:
		    case 2:
		    case 4:
		      return b + 250;
		    case 8:
		    case 16:
		    case 32:
		    case 64:
		    case 128:
		    case 256:
		    case 512:
		    case 1024:
		    case 2048:
		    case 4096:
		    case 8192:
		    case 16384:
		    case 32768:
		    case 65536:
		    case 131072:
		    case 262144:
		    case 524288:
		    case 1048576:
		    case 2097152:
		      return b + 5E3;
		    case 4194304:
		    case 8388608:
		    case 16777216:
		    case 33554432:
		    case 67108864:
		      return -1;
		    case 134217728:
		    case 268435456:
		    case 536870912:
		    case 1073741824:
		      return -1;
		    default:
		      return -1;
		  }
		}
		function wc(a, b) {
		  for (var c = a.suspendedLanes, d = a.pingedLanes, e = a.expirationTimes, f = a.pendingLanes; 0 < f;) {
		    var g = 31 - oc(f),
		      h = 1 << g,
		      k = e[g];
		    if (-1 === k) {
		      if (0 === (h & c) || 0 !== (h & d)) e[g] = vc(h, b);
		    } else k <= b && (a.expiredLanes |= h);
		    f &= ~h;
		  }
		}
		function xc(a) {
		  a = a.pendingLanes & -1073741825;
		  return 0 !== a ? a : a & 1073741824 ? 1073741824 : 0;
		}
		function yc() {
		  var a = rc;
		  rc <<= 1;
		  0 === (rc & 4194240) && (rc = 64);
		  return a;
		}
		function zc(a) {
		  for (var b = [], c = 0; 31 > c; c++) b.push(a);
		  return b;
		}
		function Ac(a, b, c) {
		  a.pendingLanes |= b;
		  536870912 !== b && (a.suspendedLanes = 0, a.pingedLanes = 0);
		  a = a.eventTimes;
		  b = 31 - oc(b);
		  a[b] = c;
		}
		function Bc(a, b) {
		  var c = a.pendingLanes & ~b;
		  a.pendingLanes = b;
		  a.suspendedLanes = 0;
		  a.pingedLanes = 0;
		  a.expiredLanes &= b;
		  a.mutableReadLanes &= b;
		  a.entangledLanes &= b;
		  b = a.entanglements;
		  var d = a.eventTimes;
		  for (a = a.expirationTimes; 0 < c;) {
		    var e = 31 - oc(c),
		      f = 1 << e;
		    b[e] = 0;
		    d[e] = -1;
		    a[e] = -1;
		    c &= ~f;
		  }
		}
		function Cc(a, b) {
		  var c = a.entangledLanes |= b;
		  for (a = a.entanglements; c;) {
		    var d = 31 - oc(c),
		      e = 1 << d;
		    e & b | a[d] & b && (a[d] |= b);
		    c &= ~e;
		  }
		}
		var C = 0;
		function Dc(a) {
		  a &= -a;
		  return 1 < a ? 4 < a ? 0 !== (a & 268435455) ? 16 : 536870912 : 4 : 1;
		}
		var Ec,
		  Fc,
		  Gc,
		  Hc,
		  Ic,
		  Jc = !1,
		  Kc = [],
		  Lc = null,
		  Mc = null,
		  Nc = null,
		  Oc = new Map(),
		  Pc = new Map(),
		  Qc = [],
		  Rc = "mousedown mouseup touchcancel touchend touchstart auxclick dblclick pointercancel pointerdown pointerup dragend dragstart drop compositionend compositionstart keydown keypress keyup input textInput copy cut paste click change contextmenu reset submit".split(" ");
		function Sc(a, b) {
		  switch (a) {
		    case "focusin":
		    case "focusout":
		      Lc = null;
		      break;
		    case "dragenter":
		    case "dragleave":
		      Mc = null;
		      break;
		    case "mouseover":
		    case "mouseout":
		      Nc = null;
		      break;
		    case "pointerover":
		    case "pointerout":
		      Oc.delete(b.pointerId);
		      break;
		    case "gotpointercapture":
		    case "lostpointercapture":
		      Pc.delete(b.pointerId);
		  }
		}
		function Tc(a, b, c, d, e, f) {
		  if (null === a || a.nativeEvent !== f) return a = {
		    blockedOn: b,
		    domEventName: c,
		    eventSystemFlags: d,
		    nativeEvent: f,
		    targetContainers: [e]
		  }, null !== b && (b = Cb(b), null !== b && Fc(b)), a;
		  a.eventSystemFlags |= d;
		  b = a.targetContainers;
		  null !== e && -1 === b.indexOf(e) && b.push(e);
		  return a;
		}
		function Uc(a, b, c, d, e) {
		  switch (b) {
		    case "focusin":
		      return Lc = Tc(Lc, a, b, c, d, e), !0;
		    case "dragenter":
		      return Mc = Tc(Mc, a, b, c, d, e), !0;
		    case "mouseover":
		      return Nc = Tc(Nc, a, b, c, d, e), !0;
		    case "pointerover":
		      var f = e.pointerId;
		      Oc.set(f, Tc(Oc.get(f) || null, a, b, c, d, e));
		      return !0;
		    case "gotpointercapture":
		      return f = e.pointerId, Pc.set(f, Tc(Pc.get(f) || null, a, b, c, d, e)), !0;
		  }
		  return !1;
		}
		function Vc(a) {
		  var b = Wc(a.target);
		  if (null !== b) {
		    var c = Vb(b);
		    if (null !== c) if (b = c.tag, 13 === b) {
		      if (b = Wb(c), null !== b) {
		        a.blockedOn = b;
		        Ic(a.priority, function () {
		          Gc(c);
		        });
		        return;
		      }
		    } else if (3 === b && c.stateNode.current.memoizedState.isDehydrated) {
		      a.blockedOn = 3 === c.tag ? c.stateNode.containerInfo : null;
		      return;
		    }
		  }
		  a.blockedOn = null;
		}
		function Xc(a) {
		  if (null !== a.blockedOn) return !1;
		  for (var b = a.targetContainers; 0 < b.length;) {
		    var c = Yc(a.domEventName, a.eventSystemFlags, b[0], a.nativeEvent);
		    if (null === c) {
		      c = a.nativeEvent;
		      var d = new c.constructor(c.type, c);
		      wb = d;
		      c.target.dispatchEvent(d);
		      wb = null;
		    } else return b = Cb(c), null !== b && Fc(b), a.blockedOn = c, !1;
		    b.shift();
		  }
		  return !0;
		}
		function Zc(a, b, c) {
		  Xc(a) && c.delete(b);
		}
		function $c() {
		  Jc = !1;
		  null !== Lc && Xc(Lc) && (Lc = null);
		  null !== Mc && Xc(Mc) && (Mc = null);
		  null !== Nc && Xc(Nc) && (Nc = null);
		  Oc.forEach(Zc);
		  Pc.forEach(Zc);
		}
		function ad(a, b) {
		  a.blockedOn === b && (a.blockedOn = null, Jc || (Jc = !0, ca.unstable_scheduleCallback(ca.unstable_NormalPriority, $c)));
		}
		function bd(a) {
		  function b(b) {
		    return ad(b, a);
		  }
		  if (0 < Kc.length) {
		    ad(Kc[0], a);
		    for (var c = 1; c < Kc.length; c++) {
		      var d = Kc[c];
		      d.blockedOn === a && (d.blockedOn = null);
		    }
		  }
		  null !== Lc && ad(Lc, a);
		  null !== Mc && ad(Mc, a);
		  null !== Nc && ad(Nc, a);
		  Oc.forEach(b);
		  Pc.forEach(b);
		  for (c = 0; c < Qc.length; c++) d = Qc[c], d.blockedOn === a && (d.blockedOn = null);
		  for (; 0 < Qc.length && (c = Qc[0], null === c.blockedOn);) Vc(c), null === c.blockedOn && Qc.shift();
		}
		var cd = ua.ReactCurrentBatchConfig,
		  dd = !0;
		function ed(a, b, c, d) {
		  var e = C,
		    f = cd.transition;
		  cd.transition = null;
		  try {
		    C = 1, fd(a, b, c, d);
		  } finally {
		    C = e, cd.transition = f;
		  }
		}
		function gd(a, b, c, d) {
		  var e = C,
		    f = cd.transition;
		  cd.transition = null;
		  try {
		    C = 4, fd(a, b, c, d);
		  } finally {
		    C = e, cd.transition = f;
		  }
		}
		function fd(a, b, c, d) {
		  if (dd) {
		    var e = Yc(a, b, c, d);
		    if (null === e) hd(a, b, d, id, c), Sc(a, d);else if (Uc(e, a, b, c, d)) d.stopPropagation();else if (Sc(a, d), b & 4 && -1 < Rc.indexOf(a)) {
		      for (; null !== e;) {
		        var f = Cb(e);
		        null !== f && Ec(f);
		        f = Yc(a, b, c, d);
		        null === f && hd(a, b, d, id, c);
		        if (f === e) break;
		        e = f;
		      }
		      null !== e && d.stopPropagation();
		    } else hd(a, b, d, null, c);
		  }
		}
		var id = null;
		function Yc(a, b, c, d) {
		  id = null;
		  a = xb(d);
		  a = Wc(a);
		  if (null !== a) if (b = Vb(a), null === b) a = null;else if (c = b.tag, 13 === c) {
		    a = Wb(b);
		    if (null !== a) return a;
		    a = null;
		  } else if (3 === c) {
		    if (b.stateNode.current.memoizedState.isDehydrated) return 3 === b.tag ? b.stateNode.containerInfo : null;
		    a = null;
		  } else b !== a && (a = null);
		  id = a;
		  return null;
		}
		function jd(a) {
		  switch (a) {
		    case "cancel":
		    case "click":
		    case "close":
		    case "contextmenu":
		    case "copy":
		    case "cut":
		    case "auxclick":
		    case "dblclick":
		    case "dragend":
		    case "dragstart":
		    case "drop":
		    case "focusin":
		    case "focusout":
		    case "input":
		    case "invalid":
		    case "keydown":
		    case "keypress":
		    case "keyup":
		    case "mousedown":
		    case "mouseup":
		    case "paste":
		    case "pause":
		    case "play":
		    case "pointercancel":
		    case "pointerdown":
		    case "pointerup":
		    case "ratechange":
		    case "reset":
		    case "resize":
		    case "seeked":
		    case "submit":
		    case "touchcancel":
		    case "touchend":
		    case "touchstart":
		    case "volumechange":
		    case "change":
		    case "selectionchange":
		    case "textInput":
		    case "compositionstart":
		    case "compositionend":
		    case "compositionupdate":
		    case "beforeblur":
		    case "afterblur":
		    case "beforeinput":
		    case "blur":
		    case "fullscreenchange":
		    case "focus":
		    case "hashchange":
		    case "popstate":
		    case "select":
		    case "selectstart":
		      return 1;
		    case "drag":
		    case "dragenter":
		    case "dragexit":
		    case "dragleave":
		    case "dragover":
		    case "mousemove":
		    case "mouseout":
		    case "mouseover":
		    case "pointermove":
		    case "pointerout":
		    case "pointerover":
		    case "scroll":
		    case "toggle":
		    case "touchmove":
		    case "wheel":
		    case "mouseenter":
		    case "mouseleave":
		    case "pointerenter":
		    case "pointerleave":
		      return 4;
		    case "message":
		      switch (ec()) {
		        case fc:
		          return 1;
		        case gc:
		          return 4;
		        case hc:
		        case ic:
		          return 16;
		        case jc:
		          return 536870912;
		        default:
		          return 16;
		      }
		    default:
		      return 16;
		  }
		}
		var kd = null,
		  ld = null,
		  md = null;
		function nd() {
		  if (md) return md;
		  var a,
		    b = ld,
		    c = b.length,
		    d,
		    e = "value" in kd ? kd.value : kd.textContent,
		    f = e.length;
		  for (a = 0; a < c && b[a] === e[a]; a++);
		  var g = c - a;
		  for (d = 1; d <= g && b[c - d] === e[f - d]; d++);
		  return md = e.slice(a, 1 < d ? 1 - d : void 0);
		}
		function od(a) {
		  var b = a.keyCode;
		  "charCode" in a ? (a = a.charCode, 0 === a && 13 === b && (a = 13)) : a = b;
		  10 === a && (a = 13);
		  return 32 <= a || 13 === a ? a : 0;
		}
		function pd() {
		  return !0;
		}
		function qd() {
		  return !1;
		}
		function rd(a) {
		  function b(b, d, e, f, g) {
		    this._reactName = b;
		    this._targetInst = e;
		    this.type = d;
		    this.nativeEvent = f;
		    this.target = g;
		    this.currentTarget = null;
		    for (var c in a) a.hasOwnProperty(c) && (b = a[c], this[c] = b ? b(f) : f[c]);
		    this.isDefaultPrevented = (null != f.defaultPrevented ? f.defaultPrevented : !1 === f.returnValue) ? pd : qd;
		    this.isPropagationStopped = qd;
		    return this;
		  }
		  A(b.prototype, {
		    preventDefault: function () {
		      this.defaultPrevented = !0;
		      var a = this.nativeEvent;
		      a && (a.preventDefault ? a.preventDefault() : "unknown" !== typeof a.returnValue && (a.returnValue = !1), this.isDefaultPrevented = pd);
		    },
		    stopPropagation: function () {
		      var a = this.nativeEvent;
		      a && (a.stopPropagation ? a.stopPropagation() : "unknown" !== typeof a.cancelBubble && (a.cancelBubble = !0), this.isPropagationStopped = pd);
		    },
		    persist: function () {},
		    isPersistent: pd
		  });
		  return b;
		}
		var sd = {
		    eventPhase: 0,
		    bubbles: 0,
		    cancelable: 0,
		    timeStamp: function (a) {
		      return a.timeStamp || Date.now();
		    },
		    defaultPrevented: 0,
		    isTrusted: 0
		  },
		  td = rd(sd),
		  ud = A({}, sd, {
		    view: 0,
		    detail: 0
		  }),
		  vd = rd(ud),
		  wd,
		  xd,
		  yd,
		  Ad = A({}, ud, {
		    screenX: 0,
		    screenY: 0,
		    clientX: 0,
		    clientY: 0,
		    pageX: 0,
		    pageY: 0,
		    ctrlKey: 0,
		    shiftKey: 0,
		    altKey: 0,
		    metaKey: 0,
		    getModifierState: zd,
		    button: 0,
		    buttons: 0,
		    relatedTarget: function (a) {
		      return void 0 === a.relatedTarget ? a.fromElement === a.srcElement ? a.toElement : a.fromElement : a.relatedTarget;
		    },
		    movementX: function (a) {
		      if ("movementX" in a) return a.movementX;
		      a !== yd && (yd && "mousemove" === a.type ? (wd = a.screenX - yd.screenX, xd = a.screenY - yd.screenY) : xd = wd = 0, yd = a);
		      return wd;
		    },
		    movementY: function (a) {
		      return "movementY" in a ? a.movementY : xd;
		    }
		  }),
		  Bd = rd(Ad),
		  Cd = A({}, Ad, {
		    dataTransfer: 0
		  }),
		  Dd = rd(Cd),
		  Ed = A({}, ud, {
		    relatedTarget: 0
		  }),
		  Fd = rd(Ed),
		  Gd = A({}, sd, {
		    animationName: 0,
		    elapsedTime: 0,
		    pseudoElement: 0
		  }),
		  Hd = rd(Gd),
		  Id = A({}, sd, {
		    clipboardData: function (a) {
		      return "clipboardData" in a ? a.clipboardData : window.clipboardData;
		    }
		  }),
		  Jd = rd(Id),
		  Kd = A({}, sd, {
		    data: 0
		  }),
		  Ld = rd(Kd),
		  Md = {
		    Esc: "Escape",
		    Spacebar: " ",
		    Left: "ArrowLeft",
		    Up: "ArrowUp",
		    Right: "ArrowRight",
		    Down: "ArrowDown",
		    Del: "Delete",
		    Win: "OS",
		    Menu: "ContextMenu",
		    Apps: "ContextMenu",
		    Scroll: "ScrollLock",
		    MozPrintableKey: "Unidentified"
		  },
		  Nd = {
		    8: "Backspace",
		    9: "Tab",
		    12: "Clear",
		    13: "Enter",
		    16: "Shift",
		    17: "Control",
		    18: "Alt",
		    19: "Pause",
		    20: "CapsLock",
		    27: "Escape",
		    32: " ",
		    33: "PageUp",
		    34: "PageDown",
		    35: "End",
		    36: "Home",
		    37: "ArrowLeft",
		    38: "ArrowUp",
		    39: "ArrowRight",
		    40: "ArrowDown",
		    45: "Insert",
		    46: "Delete",
		    112: "F1",
		    113: "F2",
		    114: "F3",
		    115: "F4",
		    116: "F5",
		    117: "F6",
		    118: "F7",
		    119: "F8",
		    120: "F9",
		    121: "F10",
		    122: "F11",
		    123: "F12",
		    144: "NumLock",
		    145: "ScrollLock",
		    224: "Meta"
		  },
		  Od = {
		    Alt: "altKey",
		    Control: "ctrlKey",
		    Meta: "metaKey",
		    Shift: "shiftKey"
		  };
		function Pd(a) {
		  var b = this.nativeEvent;
		  return b.getModifierState ? b.getModifierState(a) : (a = Od[a]) ? !!b[a] : !1;
		}
		function zd() {
		  return Pd;
		}
		var Qd = A({}, ud, {
		    key: function (a) {
		      if (a.key) {
		        var b = Md[a.key] || a.key;
		        if ("Unidentified" !== b) return b;
		      }
		      return "keypress" === a.type ? (a = od(a), 13 === a ? "Enter" : String.fromCharCode(a)) : "keydown" === a.type || "keyup" === a.type ? Nd[a.keyCode] || "Unidentified" : "";
		    },
		    code: 0,
		    location: 0,
		    ctrlKey: 0,
		    shiftKey: 0,
		    altKey: 0,
		    metaKey: 0,
		    repeat: 0,
		    locale: 0,
		    getModifierState: zd,
		    charCode: function (a) {
		      return "keypress" === a.type ? od(a) : 0;
		    },
		    keyCode: function (a) {
		      return "keydown" === a.type || "keyup" === a.type ? a.keyCode : 0;
		    },
		    which: function (a) {
		      return "keypress" === a.type ? od(a) : "keydown" === a.type || "keyup" === a.type ? a.keyCode : 0;
		    }
		  }),
		  Rd = rd(Qd),
		  Sd = A({}, Ad, {
		    pointerId: 0,
		    width: 0,
		    height: 0,
		    pressure: 0,
		    tangentialPressure: 0,
		    tiltX: 0,
		    tiltY: 0,
		    twist: 0,
		    pointerType: 0,
		    isPrimary: 0
		  }),
		  Td = rd(Sd),
		  Ud = A({}, ud, {
		    touches: 0,
		    targetTouches: 0,
		    changedTouches: 0,
		    altKey: 0,
		    metaKey: 0,
		    ctrlKey: 0,
		    shiftKey: 0,
		    getModifierState: zd
		  }),
		  Vd = rd(Ud),
		  Wd = A({}, sd, {
		    propertyName: 0,
		    elapsedTime: 0,
		    pseudoElement: 0
		  }),
		  Xd = rd(Wd),
		  Yd = A({}, Ad, {
		    deltaX: function (a) {
		      return "deltaX" in a ? a.deltaX : "wheelDeltaX" in a ? -a.wheelDeltaX : 0;
		    },
		    deltaY: function (a) {
		      return "deltaY" in a ? a.deltaY : "wheelDeltaY" in a ? -a.wheelDeltaY : "wheelDelta" in a ? -a.wheelDelta : 0;
		    },
		    deltaZ: 0,
		    deltaMode: 0
		  }),
		  Zd = rd(Yd),
		  $d = [9, 13, 27, 32],
		  ae = ia && "CompositionEvent" in window,
		  be = null;
		ia && "documentMode" in document && (be = document.documentMode);
		var ce = ia && "TextEvent" in window && !be,
		  de = ia && (!ae || be && 8 < be && 11 >= be),
		  ee = String.fromCharCode(32),
		  fe = !1;
		function ge(a, b) {
		  switch (a) {
		    case "keyup":
		      return -1 !== $d.indexOf(b.keyCode);
		    case "keydown":
		      return 229 !== b.keyCode;
		    case "keypress":
		    case "mousedown":
		    case "focusout":
		      return !0;
		    default:
		      return !1;
		  }
		}
		function he(a) {
		  a = a.detail;
		  return "object" === typeof a && "data" in a ? a.data : null;
		}
		var ie = !1;
		function je(a, b) {
		  switch (a) {
		    case "compositionend":
		      return he(b);
		    case "keypress":
		      if (32 !== b.which) return null;
		      fe = !0;
		      return ee;
		    case "textInput":
		      return a = b.data, a === ee && fe ? null : a;
		    default:
		      return null;
		  }
		}
		function ke(a, b) {
		  if (ie) return "compositionend" === a || !ae && ge(a, b) ? (a = nd(), md = ld = kd = null, ie = !1, a) : null;
		  switch (a) {
		    case "paste":
		      return null;
		    case "keypress":
		      if (!(b.ctrlKey || b.altKey || b.metaKey) || b.ctrlKey && b.altKey) {
		        if (b.char && 1 < b.char.length) return b.char;
		        if (b.which) return String.fromCharCode(b.which);
		      }
		      return null;
		    case "compositionend":
		      return de && "ko" !== b.locale ? null : b.data;
		    default:
		      return null;
		  }
		}
		var le = {
		  color: !0,
		  date: !0,
		  datetime: !0,
		  "datetime-local": !0,
		  email: !0,
		  month: !0,
		  number: !0,
		  password: !0,
		  range: !0,
		  search: !0,
		  tel: !0,
		  text: !0,
		  time: !0,
		  url: !0,
		  week: !0
		};
		function me(a) {
		  var b = a && a.nodeName && a.nodeName.toLowerCase();
		  return "input" === b ? !!le[a.type] : "textarea" === b ? !0 : !1;
		}
		function ne(a, b, c, d) {
		  Eb(d);
		  b = oe(b, "onChange");
		  0 < b.length && (c = new td("onChange", "change", null, c, d), a.push({
		    event: c,
		    listeners: b
		  }));
		}
		var pe = null,
		  qe = null;
		function re(a) {
		  se(a, 0);
		}
		function te(a) {
		  var b = ue(a);
		  if (Wa(b)) return a;
		}
		function ve(a, b) {
		  if ("change" === a) return b;
		}
		var we = !1;
		if (ia) {
		  var xe;
		  if (ia) {
		    var ye = "oninput" in document;
		    if (!ye) {
		      var ze = document.createElement("div");
		      ze.setAttribute("oninput", "return;");
		      ye = "function" === typeof ze.oninput;
		    }
		    xe = ye;
		  } else xe = !1;
		  we = xe && (!document.documentMode || 9 < document.documentMode);
		}
		function Ae() {
		  pe && (pe.detachEvent("onpropertychange", Be), qe = pe = null);
		}
		function Be(a) {
		  if ("value" === a.propertyName && te(qe)) {
		    var b = [];
		    ne(b, qe, a, xb(a));
		    Jb(re, b);
		  }
		}
		function Ce(a, b, c) {
		  "focusin" === a ? (Ae(), pe = b, qe = c, pe.attachEvent("onpropertychange", Be)) : "focusout" === a && Ae();
		}
		function De(a) {
		  if ("selectionchange" === a || "keyup" === a || "keydown" === a) return te(qe);
		}
		function Ee(a, b) {
		  if ("click" === a) return te(b);
		}
		function Fe(a, b) {
		  if ("input" === a || "change" === a) return te(b);
		}
		function Ge(a, b) {
		  return a === b && (0 !== a || 1 / a === 1 / b) || a !== a && b !== b;
		}
		var He = "function" === typeof Object.is ? Object.is : Ge;
		function Ie(a, b) {
		  if (He(a, b)) return !0;
		  if ("object" !== typeof a || null === a || "object" !== typeof b || null === b) return !1;
		  var c = Object.keys(a),
		    d = Object.keys(b);
		  if (c.length !== d.length) return !1;
		  for (d = 0; d < c.length; d++) {
		    var e = c[d];
		    if (!ja.call(b, e) || !He(a[e], b[e])) return !1;
		  }
		  return !0;
		}
		function Je(a) {
		  for (; a && a.firstChild;) a = a.firstChild;
		  return a;
		}
		function Ke(a, b) {
		  var c = Je(a);
		  a = 0;
		  for (var d; c;) {
		    if (3 === c.nodeType) {
		      d = a + c.textContent.length;
		      if (a <= b && d >= b) return {
		        node: c,
		        offset: b - a
		      };
		      a = d;
		    }
		    a: {
		      for (; c;) {
		        if (c.nextSibling) {
		          c = c.nextSibling;
		          break a;
		        }
		        c = c.parentNode;
		      }
		      c = void 0;
		    }
		    c = Je(c);
		  }
		}
		function Le(a, b) {
		  return a && b ? a === b ? !0 : a && 3 === a.nodeType ? !1 : b && 3 === b.nodeType ? Le(a, b.parentNode) : "contains" in a ? a.contains(b) : a.compareDocumentPosition ? !!(a.compareDocumentPosition(b) & 16) : !1 : !1;
		}
		function Me() {
		  for (var a = window, b = Xa(); b instanceof a.HTMLIFrameElement;) {
		    try {
		      var c = "string" === typeof b.contentWindow.location.href;
		    } catch (d) {
		      c = !1;
		    }
		    if (c) a = b.contentWindow;else break;
		    b = Xa(a.document);
		  }
		  return b;
		}
		function Ne(a) {
		  var b = a && a.nodeName && a.nodeName.toLowerCase();
		  return b && ("input" === b && ("text" === a.type || "search" === a.type || "tel" === a.type || "url" === a.type || "password" === a.type) || "textarea" === b || "true" === a.contentEditable);
		}
		function Oe(a) {
		  var b = Me(),
		    c = a.focusedElem,
		    d = a.selectionRange;
		  if (b !== c && c && c.ownerDocument && Le(c.ownerDocument.documentElement, c)) {
		    if (null !== d && Ne(c)) if (b = d.start, a = d.end, void 0 === a && (a = b), "selectionStart" in c) c.selectionStart = b, c.selectionEnd = Math.min(a, c.value.length);else if (a = (b = c.ownerDocument || document) && b.defaultView || window, a.getSelection) {
		      a = a.getSelection();
		      var e = c.textContent.length,
		        f = Math.min(d.start, e);
		      d = void 0 === d.end ? f : Math.min(d.end, e);
		      !a.extend && f > d && (e = d, d = f, f = e);
		      e = Ke(c, f);
		      var g = Ke(c, d);
		      e && g && (1 !== a.rangeCount || a.anchorNode !== e.node || a.anchorOffset !== e.offset || a.focusNode !== g.node || a.focusOffset !== g.offset) && (b = b.createRange(), b.setStart(e.node, e.offset), a.removeAllRanges(), f > d ? (a.addRange(b), a.extend(g.node, g.offset)) : (b.setEnd(g.node, g.offset), a.addRange(b)));
		    }
		    b = [];
		    for (a = c; a = a.parentNode;) 1 === a.nodeType && b.push({
		      element: a,
		      left: a.scrollLeft,
		      top: a.scrollTop
		    });
		    "function" === typeof c.focus && c.focus();
		    for (c = 0; c < b.length; c++) a = b[c], a.element.scrollLeft = a.left, a.element.scrollTop = a.top;
		  }
		}
		var Pe = ia && "documentMode" in document && 11 >= document.documentMode,
		  Qe = null,
		  Re = null,
		  Se = null,
		  Te = !1;
		function Ue(a, b, c) {
		  var d = c.window === c ? c.document : 9 === c.nodeType ? c : c.ownerDocument;
		  Te || null == Qe || Qe !== Xa(d) || (d = Qe, "selectionStart" in d && Ne(d) ? d = {
		    start: d.selectionStart,
		    end: d.selectionEnd
		  } : (d = (d.ownerDocument && d.ownerDocument.defaultView || window).getSelection(), d = {
		    anchorNode: d.anchorNode,
		    anchorOffset: d.anchorOffset,
		    focusNode: d.focusNode,
		    focusOffset: d.focusOffset
		  }), Se && Ie(Se, d) || (Se = d, d = oe(Re, "onSelect"), 0 < d.length && (b = new td("onSelect", "select", null, b, c), a.push({
		    event: b,
		    listeners: d
		  }), b.target = Qe)));
		}
		function Ve(a, b) {
		  var c = {};
		  c[a.toLowerCase()] = b.toLowerCase();
		  c["Webkit" + a] = "webkit" + b;
		  c["Moz" + a] = "moz" + b;
		  return c;
		}
		var We = {
		    animationend: Ve("Animation", "AnimationEnd"),
		    animationiteration: Ve("Animation", "AnimationIteration"),
		    animationstart: Ve("Animation", "AnimationStart"),
		    transitionend: Ve("Transition", "TransitionEnd")
		  },
		  Xe = {},
		  Ye = {};
		ia && (Ye = document.createElement("div").style, "AnimationEvent" in window || (delete We.animationend.animation, delete We.animationiteration.animation, delete We.animationstart.animation), "TransitionEvent" in window || delete We.transitionend.transition);
		function Ze(a) {
		  if (Xe[a]) return Xe[a];
		  if (!We[a]) return a;
		  var b = We[a],
		    c;
		  for (c in b) if (b.hasOwnProperty(c) && c in Ye) return Xe[a] = b[c];
		  return a;
		}
		var $e = Ze("animationend"),
		  af = Ze("animationiteration"),
		  bf = Ze("animationstart"),
		  cf = Ze("transitionend"),
		  df = new Map(),
		  ef = "abort auxClick cancel canPlay canPlayThrough click close contextMenu copy cut drag dragEnd dragEnter dragExit dragLeave dragOver dragStart drop durationChange emptied encrypted ended error gotPointerCapture input invalid keyDown keyPress keyUp load loadedData loadedMetadata loadStart lostPointerCapture mouseDown mouseMove mouseOut mouseOver mouseUp paste pause play playing pointerCancel pointerDown pointerMove pointerOut pointerOver pointerUp progress rateChange reset resize seeked seeking stalled submit suspend timeUpdate touchCancel touchEnd touchStart volumeChange scroll toggle touchMove waiting wheel".split(" ");
		function ff(a, b) {
		  df.set(a, b);
		  fa(b, [a]);
		}
		for (var gf = 0; gf < ef.length; gf++) {
		  var hf = ef[gf],
		    jf = hf.toLowerCase(),
		    kf = hf[0].toUpperCase() + hf.slice(1);
		  ff(jf, "on" + kf);
		}
		ff($e, "onAnimationEnd");
		ff(af, "onAnimationIteration");
		ff(bf, "onAnimationStart");
		ff("dblclick", "onDoubleClick");
		ff("focusin", "onFocus");
		ff("focusout", "onBlur");
		ff(cf, "onTransitionEnd");
		ha("onMouseEnter", ["mouseout", "mouseover"]);
		ha("onMouseLeave", ["mouseout", "mouseover"]);
		ha("onPointerEnter", ["pointerout", "pointerover"]);
		ha("onPointerLeave", ["pointerout", "pointerover"]);
		fa("onChange", "change click focusin focusout input keydown keyup selectionchange".split(" "));
		fa("onSelect", "focusout contextmenu dragend focusin keydown keyup mousedown mouseup selectionchange".split(" "));
		fa("onBeforeInput", ["compositionend", "keypress", "textInput", "paste"]);
		fa("onCompositionEnd", "compositionend focusout keydown keypress keyup mousedown".split(" "));
		fa("onCompositionStart", "compositionstart focusout keydown keypress keyup mousedown".split(" "));
		fa("onCompositionUpdate", "compositionupdate focusout keydown keypress keyup mousedown".split(" "));
		var lf = "abort canplay canplaythrough durationchange emptied encrypted ended error loadeddata loadedmetadata loadstart pause play playing progress ratechange resize seeked seeking stalled suspend timeupdate volumechange waiting".split(" "),
		  mf = new Set("cancel close invalid load scroll toggle".split(" ").concat(lf));
		function nf(a, b, c) {
		  var d = a.type || "unknown-event";
		  a.currentTarget = c;
		  Ub(d, b, void 0, a);
		  a.currentTarget = null;
		}
		function se(a, b) {
		  b = 0 !== (b & 4);
		  for (var c = 0; c < a.length; c++) {
		    var d = a[c],
		      e = d.event;
		    d = d.listeners;
		    a: {
		      var f = void 0;
		      if (b) for (var g = d.length - 1; 0 <= g; g--) {
		        var h = d[g],
		          k = h.instance,
		          l = h.currentTarget;
		        h = h.listener;
		        if (k !== f && e.isPropagationStopped()) break a;
		        nf(e, h, l);
		        f = k;
		      } else for (g = 0; g < d.length; g++) {
		        h = d[g];
		        k = h.instance;
		        l = h.currentTarget;
		        h = h.listener;
		        if (k !== f && e.isPropagationStopped()) break a;
		        nf(e, h, l);
		        f = k;
		      }
		    }
		  }
		  if (Qb) throw a = Rb, Qb = !1, Rb = null, a;
		}
		function D(a, b) {
		  var c = b[of];
		  void 0 === c && (c = b[of] = new Set());
		  var d = a + "__bubble";
		  c.has(d) || (pf(b, a, 2, !1), c.add(d));
		}
		function qf(a, b, c) {
		  var d = 0;
		  b && (d |= 4);
		  pf(c, a, d, b);
		}
		var rf = "_reactListening" + Math.random().toString(36).slice(2);
		function sf(a) {
		  if (!a[rf]) {
		    a[rf] = !0;
		    da.forEach(function (b) {
		      "selectionchange" !== b && (mf.has(b) || qf(b, !1, a), qf(b, !0, a));
		    });
		    var b = 9 === a.nodeType ? a : a.ownerDocument;
		    null === b || b[rf] || (b[rf] = !0, qf("selectionchange", !1, b));
		  }
		}
		function pf(a, b, c, d) {
		  switch (jd(b)) {
		    case 1:
		      var e = ed;
		      break;
		    case 4:
		      e = gd;
		      break;
		    default:
		      e = fd;
		  }
		  c = e.bind(null, b, c, a);
		  e = void 0;
		  !Lb || "touchstart" !== b && "touchmove" !== b && "wheel" !== b || (e = !0);
		  d ? void 0 !== e ? a.addEventListener(b, c, {
		    capture: !0,
		    passive: e
		  }) : a.addEventListener(b, c, !0) : void 0 !== e ? a.addEventListener(b, c, {
		    passive: e
		  }) : a.addEventListener(b, c, !1);
		}
		function hd(a, b, c, d, e) {
		  var f = d;
		  if (0 === (b & 1) && 0 === (b & 2) && null !== d) a: for (;;) {
		    if (null === d) return;
		    var g = d.tag;
		    if (3 === g || 4 === g) {
		      var h = d.stateNode.containerInfo;
		      if (h === e || 8 === h.nodeType && h.parentNode === e) break;
		      if (4 === g) for (g = d.return; null !== g;) {
		        var k = g.tag;
		        if (3 === k || 4 === k) if (k = g.stateNode.containerInfo, k === e || 8 === k.nodeType && k.parentNode === e) return;
		        g = g.return;
		      }
		      for (; null !== h;) {
		        g = Wc(h);
		        if (null === g) return;
		        k = g.tag;
		        if (5 === k || 6 === k) {
		          d = f = g;
		          continue a;
		        }
		        h = h.parentNode;
		      }
		    }
		    d = d.return;
		  }
		  Jb(function () {
		    var d = f,
		      e = xb(c),
		      g = [];
		    a: {
		      var h = df.get(a);
		      if (void 0 !== h) {
		        var k = td,
		          n = a;
		        switch (a) {
		          case "keypress":
		            if (0 === od(c)) break a;
		          case "keydown":
		          case "keyup":
		            k = Rd;
		            break;
		          case "focusin":
		            n = "focus";
		            k = Fd;
		            break;
		          case "focusout":
		            n = "blur";
		            k = Fd;
		            break;
		          case "beforeblur":
		          case "afterblur":
		            k = Fd;
		            break;
		          case "click":
		            if (2 === c.button) break a;
		          case "auxclick":
		          case "dblclick":
		          case "mousedown":
		          case "mousemove":
		          case "mouseup":
		          case "mouseout":
		          case "mouseover":
		          case "contextmenu":
		            k = Bd;
		            break;
		          case "drag":
		          case "dragend":
		          case "dragenter":
		          case "dragexit":
		          case "dragleave":
		          case "dragover":
		          case "dragstart":
		          case "drop":
		            k = Dd;
		            break;
		          case "touchcancel":
		          case "touchend":
		          case "touchmove":
		          case "touchstart":
		            k = Vd;
		            break;
		          case $e:
		          case af:
		          case bf:
		            k = Hd;
		            break;
		          case cf:
		            k = Xd;
		            break;
		          case "scroll":
		            k = vd;
		            break;
		          case "wheel":
		            k = Zd;
		            break;
		          case "copy":
		          case "cut":
		          case "paste":
		            k = Jd;
		            break;
		          case "gotpointercapture":
		          case "lostpointercapture":
		          case "pointercancel":
		          case "pointerdown":
		          case "pointermove":
		          case "pointerout":
		          case "pointerover":
		          case "pointerup":
		            k = Td;
		        }
		        var t = 0 !== (b & 4),
		          J = !t && "scroll" === a,
		          x = t ? null !== h ? h + "Capture" : null : h;
		        t = [];
		        for (var w = d, u; null !== w;) {
		          u = w;
		          var F = u.stateNode;
		          5 === u.tag && null !== F && (u = F, null !== x && (F = Kb(w, x), null != F && t.push(tf(w, F, u))));
		          if (J) break;
		          w = w.return;
		        }
		        0 < t.length && (h = new k(h, n, null, c, e), g.push({
		          event: h,
		          listeners: t
		        }));
		      }
		    }
		    if (0 === (b & 7)) {
		      a: {
		        h = "mouseover" === a || "pointerover" === a;
		        k = "mouseout" === a || "pointerout" === a;
		        if (h && c !== wb && (n = c.relatedTarget || c.fromElement) && (Wc(n) || n[uf])) break a;
		        if (k || h) {
		          h = e.window === e ? e : (h = e.ownerDocument) ? h.defaultView || h.parentWindow : window;
		          if (k) {
		            if (n = c.relatedTarget || c.toElement, k = d, n = n ? Wc(n) : null, null !== n && (J = Vb(n), n !== J || 5 !== n.tag && 6 !== n.tag)) n = null;
		          } else k = null, n = d;
		          if (k !== n) {
		            t = Bd;
		            F = "onMouseLeave";
		            x = "onMouseEnter";
		            w = "mouse";
		            if ("pointerout" === a || "pointerover" === a) t = Td, F = "onPointerLeave", x = "onPointerEnter", w = "pointer";
		            J = null == k ? h : ue(k);
		            u = null == n ? h : ue(n);
		            h = new t(F, w + "leave", k, c, e);
		            h.target = J;
		            h.relatedTarget = u;
		            F = null;
		            Wc(e) === d && (t = new t(x, w + "enter", n, c, e), t.target = u, t.relatedTarget = J, F = t);
		            J = F;
		            if (k && n) b: {
		              t = k;
		              x = n;
		              w = 0;
		              for (u = t; u; u = vf(u)) w++;
		              u = 0;
		              for (F = x; F; F = vf(F)) u++;
		              for (; 0 < w - u;) t = vf(t), w--;
		              for (; 0 < u - w;) x = vf(x), u--;
		              for (; w--;) {
		                if (t === x || null !== x && t === x.alternate) break b;
		                t = vf(t);
		                x = vf(x);
		              }
		              t = null;
		            } else t = null;
		            null !== k && wf(g, h, k, t, !1);
		            null !== n && null !== J && wf(g, J, n, t, !0);
		          }
		        }
		      }
		      a: {
		        h = d ? ue(d) : window;
		        k = h.nodeName && h.nodeName.toLowerCase();
		        if ("select" === k || "input" === k && "file" === h.type) var na = ve;else if (me(h)) {
		          if (we) na = Fe;else {
		            na = De;
		            var xa = Ce;
		          }
		        } else (k = h.nodeName) && "input" === k.toLowerCase() && ("checkbox" === h.type || "radio" === h.type) && (na = Ee);
		        if (na && (na = na(a, d))) {
		          ne(g, na, c, e);
		          break a;
		        }
		        xa && xa(a, h, d);
		        "focusout" === a && (xa = h._wrapperState) && xa.controlled && "number" === h.type && cb(h, "number", h.value);
		      }
		      xa = d ? ue(d) : window;
		      switch (a) {
		        case "focusin":
		          if (me(xa) || "true" === xa.contentEditable) Qe = xa, Re = d, Se = null;
		          break;
		        case "focusout":
		          Se = Re = Qe = null;
		          break;
		        case "mousedown":
		          Te = !0;
		          break;
		        case "contextmenu":
		        case "mouseup":
		        case "dragend":
		          Te = !1;
		          Ue(g, c, e);
		          break;
		        case "selectionchange":
		          if (Pe) break;
		        case "keydown":
		        case "keyup":
		          Ue(g, c, e);
		      }
		      var $a;
		      if (ae) b: {
		        switch (a) {
		          case "compositionstart":
		            var ba = "onCompositionStart";
		            break b;
		          case "compositionend":
		            ba = "onCompositionEnd";
		            break b;
		          case "compositionupdate":
		            ba = "onCompositionUpdate";
		            break b;
		        }
		        ba = void 0;
		      } else ie ? ge(a, c) && (ba = "onCompositionEnd") : "keydown" === a && 229 === c.keyCode && (ba = "onCompositionStart");
		      ba && (de && "ko" !== c.locale && (ie || "onCompositionStart" !== ba ? "onCompositionEnd" === ba && ie && ($a = nd()) : (kd = e, ld = "value" in kd ? kd.value : kd.textContent, ie = !0)), xa = oe(d, ba), 0 < xa.length && (ba = new Ld(ba, a, null, c, e), g.push({
		        event: ba,
		        listeners: xa
		      }), $a ? ba.data = $a : ($a = he(c), null !== $a && (ba.data = $a))));
		      if ($a = ce ? je(a, c) : ke(a, c)) d = oe(d, "onBeforeInput"), 0 < d.length && (e = new Ld("onBeforeInput", "beforeinput", null, c, e), g.push({
		        event: e,
		        listeners: d
		      }), e.data = $a);
		    }
		    se(g, b);
		  });
		}
		function tf(a, b, c) {
		  return {
		    instance: a,
		    listener: b,
		    currentTarget: c
		  };
		}
		function oe(a, b) {
		  for (var c = b + "Capture", d = []; null !== a;) {
		    var e = a,
		      f = e.stateNode;
		    5 === e.tag && null !== f && (e = f, f = Kb(a, c), null != f && d.unshift(tf(a, f, e)), f = Kb(a, b), null != f && d.push(tf(a, f, e)));
		    a = a.return;
		  }
		  return d;
		}
		function vf(a) {
		  if (null === a) return null;
		  do a = a.return; while (a && 5 !== a.tag);
		  return a ? a : null;
		}
		function wf(a, b, c, d, e) {
		  for (var f = b._reactName, g = []; null !== c && c !== d;) {
		    var h = c,
		      k = h.alternate,
		      l = h.stateNode;
		    if (null !== k && k === d) break;
		    5 === h.tag && null !== l && (h = l, e ? (k = Kb(c, f), null != k && g.unshift(tf(c, k, h))) : e || (k = Kb(c, f), null != k && g.push(tf(c, k, h))));
		    c = c.return;
		  }
		  0 !== g.length && a.push({
		    event: b,
		    listeners: g
		  });
		}
		var xf = /\r\n?/g,
		  yf = /\u0000|\uFFFD/g;
		function zf(a) {
		  return ("string" === typeof a ? a : "" + a).replace(xf, "\n").replace(yf, "");
		}
		function Af(a, b, c) {
		  b = zf(b);
		  if (zf(a) !== b && c) throw Error(p(425));
		}
		function Bf() {}
		var Cf = null,
		  Df = null;
		function Ef(a, b) {
		  return "textarea" === a || "noscript" === a || "string" === typeof b.children || "number" === typeof b.children || "object" === typeof b.dangerouslySetInnerHTML && null !== b.dangerouslySetInnerHTML && null != b.dangerouslySetInnerHTML.__html;
		}
		var Ff = "function" === typeof setTimeout ? setTimeout : void 0,
		  Gf = "function" === typeof clearTimeout ? clearTimeout : void 0,
		  Hf = "function" === typeof Promise ? Promise : void 0,
		  Jf = "function" === typeof queueMicrotask ? queueMicrotask : "undefined" !== typeof Hf ? function (a) {
		    return Hf.resolve(null).then(a).catch(If);
		  } : Ff;
		function If(a) {
		  setTimeout(function () {
		    throw a;
		  });
		}
		function Kf(a, b) {
		  var c = b,
		    d = 0;
		  do {
		    var e = c.nextSibling;
		    a.removeChild(c);
		    if (e && 8 === e.nodeType) if (c = e.data, "/$" === c) {
		      if (0 === d) {
		        a.removeChild(e);
		        bd(b);
		        return;
		      }
		      d--;
		    } else "$" !== c && "$?" !== c && "$!" !== c || d++;
		    c = e;
		  } while (c);
		  bd(b);
		}
		function Lf(a) {
		  for (; null != a; a = a.nextSibling) {
		    var b = a.nodeType;
		    if (1 === b || 3 === b) break;
		    if (8 === b) {
		      b = a.data;
		      if ("$" === b || "$!" === b || "$?" === b) break;
		      if ("/$" === b) return null;
		    }
		  }
		  return a;
		}
		function Mf(a) {
		  a = a.previousSibling;
		  for (var b = 0; a;) {
		    if (8 === a.nodeType) {
		      var c = a.data;
		      if ("$" === c || "$!" === c || "$?" === c) {
		        if (0 === b) return a;
		        b--;
		      } else "/$" === c && b++;
		    }
		    a = a.previousSibling;
		  }
		  return null;
		}
		var Nf = Math.random().toString(36).slice(2),
		  Of = "__reactFiber$" + Nf,
		  Pf = "__reactProps$" + Nf,
		  uf = "__reactContainer$" + Nf,
		  of = "__reactEvents$" + Nf,
		  Qf = "__reactListeners$" + Nf,
		  Rf = "__reactHandles$" + Nf;
		function Wc(a) {
		  var b = a[Of];
		  if (b) return b;
		  for (var c = a.parentNode; c;) {
		    if (b = c[uf] || c[Of]) {
		      c = b.alternate;
		      if (null !== b.child || null !== c && null !== c.child) for (a = Mf(a); null !== a;) {
		        if (c = a[Of]) return c;
		        a = Mf(a);
		      }
		      return b;
		    }
		    a = c;
		    c = a.parentNode;
		  }
		  return null;
		}
		function Cb(a) {
		  a = a[Of] || a[uf];
		  return !a || 5 !== a.tag && 6 !== a.tag && 13 !== a.tag && 3 !== a.tag ? null : a;
		}
		function ue(a) {
		  if (5 === a.tag || 6 === a.tag) return a.stateNode;
		  throw Error(p(33));
		}
		function Db(a) {
		  return a[Pf] || null;
		}
		var Sf = [],
		  Tf = -1;
		function Uf(a) {
		  return {
		    current: a
		  };
		}
		function E(a) {
		  0 > Tf || (a.current = Sf[Tf], Sf[Tf] = null, Tf--);
		}
		function G(a, b) {
		  Tf++;
		  Sf[Tf] = a.current;
		  a.current = b;
		}
		var Vf = {},
		  H = Uf(Vf),
		  Wf = Uf(!1),
		  Xf = Vf;
		function Yf(a, b) {
		  var c = a.type.contextTypes;
		  if (!c) return Vf;
		  var d = a.stateNode;
		  if (d && d.__reactInternalMemoizedUnmaskedChildContext === b) return d.__reactInternalMemoizedMaskedChildContext;
		  var e = {},
		    f;
		  for (f in c) e[f] = b[f];
		  d && (a = a.stateNode, a.__reactInternalMemoizedUnmaskedChildContext = b, a.__reactInternalMemoizedMaskedChildContext = e);
		  return e;
		}
		function Zf(a) {
		  a = a.childContextTypes;
		  return null !== a && void 0 !== a;
		}
		function $f() {
		  E(Wf);
		  E(H);
		}
		function ag(a, b, c) {
		  if (H.current !== Vf) throw Error(p(168));
		  G(H, b);
		  G(Wf, c);
		}
		function bg(a, b, c) {
		  var d = a.stateNode;
		  b = b.childContextTypes;
		  if ("function" !== typeof d.getChildContext) return c;
		  d = d.getChildContext();
		  for (var e in d) if (!(e in b)) throw Error(p(108, Ra(a) || "Unknown", e));
		  return A({}, c, d);
		}
		function cg(a) {
		  a = (a = a.stateNode) && a.__reactInternalMemoizedMergedChildContext || Vf;
		  Xf = H.current;
		  G(H, a);
		  G(Wf, Wf.current);
		  return !0;
		}
		function dg(a, b, c) {
		  var d = a.stateNode;
		  if (!d) throw Error(p(169));
		  c ? (a = bg(a, b, Xf), d.__reactInternalMemoizedMergedChildContext = a, E(Wf), E(H), G(H, a)) : E(Wf);
		  G(Wf, c);
		}
		var eg = null,
		  fg = !1,
		  gg = !1;
		function hg(a) {
		  null === eg ? eg = [a] : eg.push(a);
		}
		function ig(a) {
		  fg = !0;
		  hg(a);
		}
		function jg() {
		  if (!gg && null !== eg) {
		    gg = !0;
		    var a = 0,
		      b = C;
		    try {
		      var c = eg;
		      for (C = 1; a < c.length; a++) {
		        var d = c[a];
		        do d = d(!0); while (null !== d);
		      }
		      eg = null;
		      fg = !1;
		    } catch (e) {
		      throw null !== eg && (eg = eg.slice(a + 1)), ac(fc, jg), e;
		    } finally {
		      C = b, gg = !1;
		    }
		  }
		  return null;
		}
		var kg = [],
		  lg = 0,
		  mg = null,
		  ng = 0,
		  og = [],
		  pg = 0,
		  qg = null,
		  rg = 1,
		  sg = "";
		function tg(a, b) {
		  kg[lg++] = ng;
		  kg[lg++] = mg;
		  mg = a;
		  ng = b;
		}
		function ug(a, b, c) {
		  og[pg++] = rg;
		  og[pg++] = sg;
		  og[pg++] = qg;
		  qg = a;
		  var d = rg;
		  a = sg;
		  var e = 32 - oc(d) - 1;
		  d &= ~(1 << e);
		  c += 1;
		  var f = 32 - oc(b) + e;
		  if (30 < f) {
		    var g = e - e % 5;
		    f = (d & (1 << g) - 1).toString(32);
		    d >>= g;
		    e -= g;
		    rg = 1 << 32 - oc(b) + e | c << e | d;
		    sg = f + a;
		  } else rg = 1 << f | c << e | d, sg = a;
		}
		function vg(a) {
		  null !== a.return && (tg(a, 1), ug(a, 1, 0));
		}
		function wg(a) {
		  for (; a === mg;) mg = kg[--lg], kg[lg] = null, ng = kg[--lg], kg[lg] = null;
		  for (; a === qg;) qg = og[--pg], og[pg] = null, sg = og[--pg], og[pg] = null, rg = og[--pg], og[pg] = null;
		}
		var xg = null,
		  yg = null,
		  I = !1,
		  zg = null;
		function Ag(a, b) {
		  var c = Bg(5, null, null, 0);
		  c.elementType = "DELETED";
		  c.stateNode = b;
		  c.return = a;
		  b = a.deletions;
		  null === b ? (a.deletions = [c], a.flags |= 16) : b.push(c);
		}
		function Cg(a, b) {
		  switch (a.tag) {
		    case 5:
		      var c = a.type;
		      b = 1 !== b.nodeType || c.toLowerCase() !== b.nodeName.toLowerCase() ? null : b;
		      return null !== b ? (a.stateNode = b, xg = a, yg = Lf(b.firstChild), !0) : !1;
		    case 6:
		      return b = "" === a.pendingProps || 3 !== b.nodeType ? null : b, null !== b ? (a.stateNode = b, xg = a, yg = null, !0) : !1;
		    case 13:
		      return b = 8 !== b.nodeType ? null : b, null !== b ? (c = null !== qg ? {
		        id: rg,
		        overflow: sg
		      } : null, a.memoizedState = {
		        dehydrated: b,
		        treeContext: c,
		        retryLane: 1073741824
		      }, c = Bg(18, null, null, 0), c.stateNode = b, c.return = a, a.child = c, xg = a, yg = null, !0) : !1;
		    default:
		      return !1;
		  }
		}
		function Dg(a) {
		  return 0 !== (a.mode & 1) && 0 === (a.flags & 128);
		}
		function Eg(a) {
		  if (I) {
		    var b = yg;
		    if (b) {
		      var c = b;
		      if (!Cg(a, b)) {
		        if (Dg(a)) throw Error(p(418));
		        b = Lf(c.nextSibling);
		        var d = xg;
		        b && Cg(a, b) ? Ag(d, c) : (a.flags = a.flags & -4097 | 2, I = !1, xg = a);
		      }
		    } else {
		      if (Dg(a)) throw Error(p(418));
		      a.flags = a.flags & -4097 | 2;
		      I = !1;
		      xg = a;
		    }
		  }
		}
		function Fg(a) {
		  for (a = a.return; null !== a && 5 !== a.tag && 3 !== a.tag && 13 !== a.tag;) a = a.return;
		  xg = a;
		}
		function Gg(a) {
		  if (a !== xg) return !1;
		  if (!I) return Fg(a), I = !0, !1;
		  var b;
		  (b = 3 !== a.tag) && !(b = 5 !== a.tag) && (b = a.type, b = "head" !== b && "body" !== b && !Ef(a.type, a.memoizedProps));
		  if (b && (b = yg)) {
		    if (Dg(a)) throw Hg(), Error(p(418));
		    for (; b;) Ag(a, b), b = Lf(b.nextSibling);
		  }
		  Fg(a);
		  if (13 === a.tag) {
		    a = a.memoizedState;
		    a = null !== a ? a.dehydrated : null;
		    if (!a) throw Error(p(317));
		    a: {
		      a = a.nextSibling;
		      for (b = 0; a;) {
		        if (8 === a.nodeType) {
		          var c = a.data;
		          if ("/$" === c) {
		            if (0 === b) {
		              yg = Lf(a.nextSibling);
		              break a;
		            }
		            b--;
		          } else "$" !== c && "$!" !== c && "$?" !== c || b++;
		        }
		        a = a.nextSibling;
		      }
		      yg = null;
		    }
		  } else yg = xg ? Lf(a.stateNode.nextSibling) : null;
		  return !0;
		}
		function Hg() {
		  for (var a = yg; a;) a = Lf(a.nextSibling);
		}
		function Ig() {
		  yg = xg = null;
		  I = !1;
		}
		function Jg(a) {
		  null === zg ? zg = [a] : zg.push(a);
		}
		var Kg = ua.ReactCurrentBatchConfig;
		function Lg(a, b, c) {
		  a = c.ref;
		  if (null !== a && "function" !== typeof a && "object" !== typeof a) {
		    if (c._owner) {
		      c = c._owner;
		      if (c) {
		        if (1 !== c.tag) throw Error(p(309));
		        var d = c.stateNode;
		      }
		      if (!d) throw Error(p(147, a));
		      var e = d,
		        f = "" + a;
		      if (null !== b && null !== b.ref && "function" === typeof b.ref && b.ref._stringRef === f) return b.ref;
		      b = function (a) {
		        var b = e.refs;
		        null === a ? delete b[f] : b[f] = a;
		      };
		      b._stringRef = f;
		      return b;
		    }
		    if ("string" !== typeof a) throw Error(p(284));
		    if (!c._owner) throw Error(p(290, a));
		  }
		  return a;
		}
		function Mg(a, b) {
		  a = Object.prototype.toString.call(b);
		  throw Error(p(31, "[object Object]" === a ? "object with keys {" + Object.keys(b).join(", ") + "}" : a));
		}
		function Ng(a) {
		  var b = a._init;
		  return b(a._payload);
		}
		function Og(a) {
		  function b(b, c) {
		    if (a) {
		      var d = b.deletions;
		      null === d ? (b.deletions = [c], b.flags |= 16) : d.push(c);
		    }
		  }
		  function c(c, d) {
		    if (!a) return null;
		    for (; null !== d;) b(c, d), d = d.sibling;
		    return null;
		  }
		  function d(a, b) {
		    for (a = new Map(); null !== b;) null !== b.key ? a.set(b.key, b) : a.set(b.index, b), b = b.sibling;
		    return a;
		  }
		  function e(a, b) {
		    a = Pg(a, b);
		    a.index = 0;
		    a.sibling = null;
		    return a;
		  }
		  function f(b, c, d) {
		    b.index = d;
		    if (!a) return b.flags |= 1048576, c;
		    d = b.alternate;
		    if (null !== d) return d = d.index, d < c ? (b.flags |= 2, c) : d;
		    b.flags |= 2;
		    return c;
		  }
		  function g(b) {
		    a && null === b.alternate && (b.flags |= 2);
		    return b;
		  }
		  function h(a, b, c, d) {
		    if (null === b || 6 !== b.tag) return b = Qg(c, a.mode, d), b.return = a, b;
		    b = e(b, c);
		    b.return = a;
		    return b;
		  }
		  function k(a, b, c, d) {
		    var f = c.type;
		    if (f === ya) return m(a, b, c.props.children, d, c.key);
		    if (null !== b && (b.elementType === f || "object" === typeof f && null !== f && f.$$typeof === Ha && Ng(f) === b.type)) return d = e(b, c.props), d.ref = Lg(a, b, c), d.return = a, d;
		    d = Rg(c.type, c.key, c.props, null, a.mode, d);
		    d.ref = Lg(a, b, c);
		    d.return = a;
		    return d;
		  }
		  function l(a, b, c, d) {
		    if (null === b || 4 !== b.tag || b.stateNode.containerInfo !== c.containerInfo || b.stateNode.implementation !== c.implementation) return b = Sg(c, a.mode, d), b.return = a, b;
		    b = e(b, c.children || []);
		    b.return = a;
		    return b;
		  }
		  function m(a, b, c, d, f) {
		    if (null === b || 7 !== b.tag) return b = Tg(c, a.mode, d, f), b.return = a, b;
		    b = e(b, c);
		    b.return = a;
		    return b;
		  }
		  function q(a, b, c) {
		    if ("string" === typeof b && "" !== b || "number" === typeof b) return b = Qg("" + b, a.mode, c), b.return = a, b;
		    if ("object" === typeof b && null !== b) {
		      switch (b.$$typeof) {
		        case va:
		          return c = Rg(b.type, b.key, b.props, null, a.mode, c), c.ref = Lg(a, null, b), c.return = a, c;
		        case wa:
		          return b = Sg(b, a.mode, c), b.return = a, b;
		        case Ha:
		          var d = b._init;
		          return q(a, d(b._payload), c);
		      }
		      if (eb(b) || Ka(b)) return b = Tg(b, a.mode, c, null), b.return = a, b;
		      Mg(a, b);
		    }
		    return null;
		  }
		  function r(a, b, c, d) {
		    var e = null !== b ? b.key : null;
		    if ("string" === typeof c && "" !== c || "number" === typeof c) return null !== e ? null : h(a, b, "" + c, d);
		    if ("object" === typeof c && null !== c) {
		      switch (c.$$typeof) {
		        case va:
		          return c.key === e ? k(a, b, c, d) : null;
		        case wa:
		          return c.key === e ? l(a, b, c, d) : null;
		        case Ha:
		          return e = c._init, r(a, b, e(c._payload), d);
		      }
		      if (eb(c) || Ka(c)) return null !== e ? null : m(a, b, c, d, null);
		      Mg(a, c);
		    }
		    return null;
		  }
		  function y(a, b, c, d, e) {
		    if ("string" === typeof d && "" !== d || "number" === typeof d) return a = a.get(c) || null, h(b, a, "" + d, e);
		    if ("object" === typeof d && null !== d) {
		      switch (d.$$typeof) {
		        case va:
		          return a = a.get(null === d.key ? c : d.key) || null, k(b, a, d, e);
		        case wa:
		          return a = a.get(null === d.key ? c : d.key) || null, l(b, a, d, e);
		        case Ha:
		          var f = d._init;
		          return y(a, b, c, f(d._payload), e);
		      }
		      if (eb(d) || Ka(d)) return a = a.get(c) || null, m(b, a, d, e, null);
		      Mg(b, d);
		    }
		    return null;
		  }
		  function n(e, g, h, k) {
		    for (var l = null, m = null, u = g, w = g = 0, x = null; null !== u && w < h.length; w++) {
		      u.index > w ? (x = u, u = null) : x = u.sibling;
		      var n = r(e, u, h[w], k);
		      if (null === n) {
		        null === u && (u = x);
		        break;
		      }
		      a && u && null === n.alternate && b(e, u);
		      g = f(n, g, w);
		      null === m ? l = n : m.sibling = n;
		      m = n;
		      u = x;
		    }
		    if (w === h.length) return c(e, u), I && tg(e, w), l;
		    if (null === u) {
		      for (; w < h.length; w++) u = q(e, h[w], k), null !== u && (g = f(u, g, w), null === m ? l = u : m.sibling = u, m = u);
		      I && tg(e, w);
		      return l;
		    }
		    for (u = d(e, u); w < h.length; w++) x = y(u, e, w, h[w], k), null !== x && (a && null !== x.alternate && u.delete(null === x.key ? w : x.key), g = f(x, g, w), null === m ? l = x : m.sibling = x, m = x);
		    a && u.forEach(function (a) {
		      return b(e, a);
		    });
		    I && tg(e, w);
		    return l;
		  }
		  function t(e, g, h, k) {
		    var l = Ka(h);
		    if ("function" !== typeof l) throw Error(p(150));
		    h = l.call(h);
		    if (null == h) throw Error(p(151));
		    for (var u = l = null, m = g, w = g = 0, x = null, n = h.next(); null !== m && !n.done; w++, n = h.next()) {
		      m.index > w ? (x = m, m = null) : x = m.sibling;
		      var t = r(e, m, n.value, k);
		      if (null === t) {
		        null === m && (m = x);
		        break;
		      }
		      a && m && null === t.alternate && b(e, m);
		      g = f(t, g, w);
		      null === u ? l = t : u.sibling = t;
		      u = t;
		      m = x;
		    }
		    if (n.done) return c(e, m), I && tg(e, w), l;
		    if (null === m) {
		      for (; !n.done; w++, n = h.next()) n = q(e, n.value, k), null !== n && (g = f(n, g, w), null === u ? l = n : u.sibling = n, u = n);
		      I && tg(e, w);
		      return l;
		    }
		    for (m = d(e, m); !n.done; w++, n = h.next()) n = y(m, e, w, n.value, k), null !== n && (a && null !== n.alternate && m.delete(null === n.key ? w : n.key), g = f(n, g, w), null === u ? l = n : u.sibling = n, u = n);
		    a && m.forEach(function (a) {
		      return b(e, a);
		    });
		    I && tg(e, w);
		    return l;
		  }
		  function J(a, d, f, h) {
		    "object" === typeof f && null !== f && f.type === ya && null === f.key && (f = f.props.children);
		    if ("object" === typeof f && null !== f) {
		      switch (f.$$typeof) {
		        case va:
		          a: {
		            for (var k = f.key, l = d; null !== l;) {
		              if (l.key === k) {
		                k = f.type;
		                if (k === ya) {
		                  if (7 === l.tag) {
		                    c(a, l.sibling);
		                    d = e(l, f.props.children);
		                    d.return = a;
		                    a = d;
		                    break a;
		                  }
		                } else if (l.elementType === k || "object" === typeof k && null !== k && k.$$typeof === Ha && Ng(k) === l.type) {
		                  c(a, l.sibling);
		                  d = e(l, f.props);
		                  d.ref = Lg(a, l, f);
		                  d.return = a;
		                  a = d;
		                  break a;
		                }
		                c(a, l);
		                break;
		              } else b(a, l);
		              l = l.sibling;
		            }
		            f.type === ya ? (d = Tg(f.props.children, a.mode, h, f.key), d.return = a, a = d) : (h = Rg(f.type, f.key, f.props, null, a.mode, h), h.ref = Lg(a, d, f), h.return = a, a = h);
		          }
		          return g(a);
		        case wa:
		          a: {
		            for (l = f.key; null !== d;) {
		              if (d.key === l) {
		                if (4 === d.tag && d.stateNode.containerInfo === f.containerInfo && d.stateNode.implementation === f.implementation) {
		                  c(a, d.sibling);
		                  d = e(d, f.children || []);
		                  d.return = a;
		                  a = d;
		                  break a;
		                } else {
		                  c(a, d);
		                  break;
		                }
		              } else b(a, d);
		              d = d.sibling;
		            }
		            d = Sg(f, a.mode, h);
		            d.return = a;
		            a = d;
		          }
		          return g(a);
		        case Ha:
		          return l = f._init, J(a, d, l(f._payload), h);
		      }
		      if (eb(f)) return n(a, d, f, h);
		      if (Ka(f)) return t(a, d, f, h);
		      Mg(a, f);
		    }
		    return "string" === typeof f && "" !== f || "number" === typeof f ? (f = "" + f, null !== d && 6 === d.tag ? (c(a, d.sibling), d = e(d, f), d.return = a, a = d) : (c(a, d), d = Qg(f, a.mode, h), d.return = a, a = d), g(a)) : c(a, d);
		  }
		  return J;
		}
		var Ug = Og(!0),
		  Vg = Og(!1),
		  Wg = Uf(null),
		  Xg = null,
		  Yg = null,
		  Zg = null;
		function $g() {
		  Zg = Yg = Xg = null;
		}
		function ah(a) {
		  var b = Wg.current;
		  E(Wg);
		  a._currentValue = b;
		}
		function bh(a, b, c) {
		  for (; null !== a;) {
		    var d = a.alternate;
		    (a.childLanes & b) !== b ? (a.childLanes |= b, null !== d && (d.childLanes |= b)) : null !== d && (d.childLanes & b) !== b && (d.childLanes |= b);
		    if (a === c) break;
		    a = a.return;
		  }
		}
		function ch(a, b) {
		  Xg = a;
		  Zg = Yg = null;
		  a = a.dependencies;
		  null !== a && null !== a.firstContext && (0 !== (a.lanes & b) && (dh = !0), a.firstContext = null);
		}
		function eh(a) {
		  var b = a._currentValue;
		  if (Zg !== a) if (a = {
		    context: a,
		    memoizedValue: b,
		    next: null
		  }, null === Yg) {
		    if (null === Xg) throw Error(p(308));
		    Yg = a;
		    Xg.dependencies = {
		      lanes: 0,
		      firstContext: a
		    };
		  } else Yg = Yg.next = a;
		  return b;
		}
		var fh = null;
		function gh(a) {
		  null === fh ? fh = [a] : fh.push(a);
		}
		function hh(a, b, c, d) {
		  var e = b.interleaved;
		  null === e ? (c.next = c, gh(b)) : (c.next = e.next, e.next = c);
		  b.interleaved = c;
		  return ih(a, d);
		}
		function ih(a, b) {
		  a.lanes |= b;
		  var c = a.alternate;
		  null !== c && (c.lanes |= b);
		  c = a;
		  for (a = a.return; null !== a;) a.childLanes |= b, c = a.alternate, null !== c && (c.childLanes |= b), c = a, a = a.return;
		  return 3 === c.tag ? c.stateNode : null;
		}
		var jh = !1;
		function kh(a) {
		  a.updateQueue = {
		    baseState: a.memoizedState,
		    firstBaseUpdate: null,
		    lastBaseUpdate: null,
		    shared: {
		      pending: null,
		      interleaved: null,
		      lanes: 0
		    },
		    effects: null
		  };
		}
		function lh(a, b) {
		  a = a.updateQueue;
		  b.updateQueue === a && (b.updateQueue = {
		    baseState: a.baseState,
		    firstBaseUpdate: a.firstBaseUpdate,
		    lastBaseUpdate: a.lastBaseUpdate,
		    shared: a.shared,
		    effects: a.effects
		  });
		}
		function mh(a, b) {
		  return {
		    eventTime: a,
		    lane: b,
		    tag: 0,
		    payload: null,
		    callback: null,
		    next: null
		  };
		}
		function nh(a, b, c) {
		  var d = a.updateQueue;
		  if (null === d) return null;
		  d = d.shared;
		  if (0 !== (K & 2)) {
		    var e = d.pending;
		    null === e ? b.next = b : (b.next = e.next, e.next = b);
		    d.pending = b;
		    return ih(a, c);
		  }
		  e = d.interleaved;
		  null === e ? (b.next = b, gh(d)) : (b.next = e.next, e.next = b);
		  d.interleaved = b;
		  return ih(a, c);
		}
		function oh(a, b, c) {
		  b = b.updateQueue;
		  if (null !== b && (b = b.shared, 0 !== (c & 4194240))) {
		    var d = b.lanes;
		    d &= a.pendingLanes;
		    c |= d;
		    b.lanes = c;
		    Cc(a, c);
		  }
		}
		function ph(a, b) {
		  var c = a.updateQueue,
		    d = a.alternate;
		  if (null !== d && (d = d.updateQueue, c === d)) {
		    var e = null,
		      f = null;
		    c = c.firstBaseUpdate;
		    if (null !== c) {
		      do {
		        var g = {
		          eventTime: c.eventTime,
		          lane: c.lane,
		          tag: c.tag,
		          payload: c.payload,
		          callback: c.callback,
		          next: null
		        };
		        null === f ? e = f = g : f = f.next = g;
		        c = c.next;
		      } while (null !== c);
		      null === f ? e = f = b : f = f.next = b;
		    } else e = f = b;
		    c = {
		      baseState: d.baseState,
		      firstBaseUpdate: e,
		      lastBaseUpdate: f,
		      shared: d.shared,
		      effects: d.effects
		    };
		    a.updateQueue = c;
		    return;
		  }
		  a = c.lastBaseUpdate;
		  null === a ? c.firstBaseUpdate = b : a.next = b;
		  c.lastBaseUpdate = b;
		}
		function qh(a, b, c, d) {
		  var e = a.updateQueue;
		  jh = !1;
		  var f = e.firstBaseUpdate,
		    g = e.lastBaseUpdate,
		    h = e.shared.pending;
		  if (null !== h) {
		    e.shared.pending = null;
		    var k = h,
		      l = k.next;
		    k.next = null;
		    null === g ? f = l : g.next = l;
		    g = k;
		    var m = a.alternate;
		    null !== m && (m = m.updateQueue, h = m.lastBaseUpdate, h !== g && (null === h ? m.firstBaseUpdate = l : h.next = l, m.lastBaseUpdate = k));
		  }
		  if (null !== f) {
		    var q = e.baseState;
		    g = 0;
		    m = l = k = null;
		    h = f;
		    do {
		      var r = h.lane,
		        y = h.eventTime;
		      if ((d & r) === r) {
		        null !== m && (m = m.next = {
		          eventTime: y,
		          lane: 0,
		          tag: h.tag,
		          payload: h.payload,
		          callback: h.callback,
		          next: null
		        });
		        a: {
		          var n = a,
		            t = h;
		          r = b;
		          y = c;
		          switch (t.tag) {
		            case 1:
		              n = t.payload;
		              if ("function" === typeof n) {
		                q = n.call(y, q, r);
		                break a;
		              }
		              q = n;
		              break a;
		            case 3:
		              n.flags = n.flags & -65537 | 128;
		            case 0:
		              n = t.payload;
		              r = "function" === typeof n ? n.call(y, q, r) : n;
		              if (null === r || void 0 === r) break a;
		              q = A({}, q, r);
		              break a;
		            case 2:
		              jh = !0;
		          }
		        }
		        null !== h.callback && 0 !== h.lane && (a.flags |= 64, r = e.effects, null === r ? e.effects = [h] : r.push(h));
		      } else y = {
		        eventTime: y,
		        lane: r,
		        tag: h.tag,
		        payload: h.payload,
		        callback: h.callback,
		        next: null
		      }, null === m ? (l = m = y, k = q) : m = m.next = y, g |= r;
		      h = h.next;
		      if (null === h) if (h = e.shared.pending, null === h) break;else r = h, h = r.next, r.next = null, e.lastBaseUpdate = r, e.shared.pending = null;
		    } while (1);
		    null === m && (k = q);
		    e.baseState = k;
		    e.firstBaseUpdate = l;
		    e.lastBaseUpdate = m;
		    b = e.shared.interleaved;
		    if (null !== b) {
		      e = b;
		      do g |= e.lane, e = e.next; while (e !== b);
		    } else null === f && (e.shared.lanes = 0);
		    rh |= g;
		    a.lanes = g;
		    a.memoizedState = q;
		  }
		}
		function sh(a, b, c) {
		  a = b.effects;
		  b.effects = null;
		  if (null !== a) for (b = 0; b < a.length; b++) {
		    var d = a[b],
		      e = d.callback;
		    if (null !== e) {
		      d.callback = null;
		      d = c;
		      if ("function" !== typeof e) throw Error(p(191, e));
		      e.call(d);
		    }
		  }
		}
		var th = {},
		  uh = Uf(th),
		  vh = Uf(th),
		  wh = Uf(th);
		function xh(a) {
		  if (a === th) throw Error(p(174));
		  return a;
		}
		function yh(a, b) {
		  G(wh, b);
		  G(vh, a);
		  G(uh, th);
		  a = b.nodeType;
		  switch (a) {
		    case 9:
		    case 11:
		      b = (b = b.documentElement) ? b.namespaceURI : lb(null, "");
		      break;
		    default:
		      a = 8 === a ? b.parentNode : b, b = a.namespaceURI || null, a = a.tagName, b = lb(b, a);
		  }
		  E(uh);
		  G(uh, b);
		}
		function zh() {
		  E(uh);
		  E(vh);
		  E(wh);
		}
		function Ah(a) {
		  xh(wh.current);
		  var b = xh(uh.current);
		  var c = lb(b, a.type);
		  b !== c && (G(vh, a), G(uh, c));
		}
		function Bh(a) {
		  vh.current === a && (E(uh), E(vh));
		}
		var L = Uf(0);
		function Ch(a) {
		  for (var b = a; null !== b;) {
		    if (13 === b.tag) {
		      var c = b.memoizedState;
		      if (null !== c && (c = c.dehydrated, null === c || "$?" === c.data || "$!" === c.data)) return b;
		    } else if (19 === b.tag && void 0 !== b.memoizedProps.revealOrder) {
		      if (0 !== (b.flags & 128)) return b;
		    } else if (null !== b.child) {
		      b.child.return = b;
		      b = b.child;
		      continue;
		    }
		    if (b === a) break;
		    for (; null === b.sibling;) {
		      if (null === b.return || b.return === a) return null;
		      b = b.return;
		    }
		    b.sibling.return = b.return;
		    b = b.sibling;
		  }
		  return null;
		}
		var Dh = [];
		function Eh() {
		  for (var a = 0; a < Dh.length; a++) Dh[a]._workInProgressVersionPrimary = null;
		  Dh.length = 0;
		}
		var Fh = ua.ReactCurrentDispatcher,
		  Gh = ua.ReactCurrentBatchConfig,
		  Hh = 0,
		  M = null,
		  N = null,
		  O = null,
		  Ih = !1,
		  Jh = !1,
		  Kh = 0,
		  Lh = 0;
		function P() {
		  throw Error(p(321));
		}
		function Mh(a, b) {
		  if (null === b) return !1;
		  for (var c = 0; c < b.length && c < a.length; c++) if (!He(a[c], b[c])) return !1;
		  return !0;
		}
		function Nh(a, b, c, d, e, f) {
		  Hh = f;
		  M = b;
		  b.memoizedState = null;
		  b.updateQueue = null;
		  b.lanes = 0;
		  Fh.current = null === a || null === a.memoizedState ? Oh : Ph;
		  a = c(d, e);
		  if (Jh) {
		    f = 0;
		    do {
		      Jh = !1;
		      Kh = 0;
		      if (25 <= f) throw Error(p(301));
		      f += 1;
		      O = N = null;
		      b.updateQueue = null;
		      Fh.current = Qh;
		      a = c(d, e);
		    } while (Jh);
		  }
		  Fh.current = Rh;
		  b = null !== N && null !== N.next;
		  Hh = 0;
		  O = N = M = null;
		  Ih = !1;
		  if (b) throw Error(p(300));
		  return a;
		}
		function Sh() {
		  var a = 0 !== Kh;
		  Kh = 0;
		  return a;
		}
		function Th() {
		  var a = {
		    memoizedState: null,
		    baseState: null,
		    baseQueue: null,
		    queue: null,
		    next: null
		  };
		  null === O ? M.memoizedState = O = a : O = O.next = a;
		  return O;
		}
		function Uh() {
		  if (null === N) {
		    var a = M.alternate;
		    a = null !== a ? a.memoizedState : null;
		  } else a = N.next;
		  var b = null === O ? M.memoizedState : O.next;
		  if (null !== b) O = b, N = a;else {
		    if (null === a) throw Error(p(310));
		    N = a;
		    a = {
		      memoizedState: N.memoizedState,
		      baseState: N.baseState,
		      baseQueue: N.baseQueue,
		      queue: N.queue,
		      next: null
		    };
		    null === O ? M.memoizedState = O = a : O = O.next = a;
		  }
		  return O;
		}
		function Vh(a, b) {
		  return "function" === typeof b ? b(a) : b;
		}
		function Wh(a) {
		  var b = Uh(),
		    c = b.queue;
		  if (null === c) throw Error(p(311));
		  c.lastRenderedReducer = a;
		  var d = N,
		    e = d.baseQueue,
		    f = c.pending;
		  if (null !== f) {
		    if (null !== e) {
		      var g = e.next;
		      e.next = f.next;
		      f.next = g;
		    }
		    d.baseQueue = e = f;
		    c.pending = null;
		  }
		  if (null !== e) {
		    f = e.next;
		    d = d.baseState;
		    var h = g = null,
		      k = null,
		      l = f;
		    do {
		      var m = l.lane;
		      if ((Hh & m) === m) null !== k && (k = k.next = {
		        lane: 0,
		        action: l.action,
		        hasEagerState: l.hasEagerState,
		        eagerState: l.eagerState,
		        next: null
		      }), d = l.hasEagerState ? l.eagerState : a(d, l.action);else {
		        var q = {
		          lane: m,
		          action: l.action,
		          hasEagerState: l.hasEagerState,
		          eagerState: l.eagerState,
		          next: null
		        };
		        null === k ? (h = k = q, g = d) : k = k.next = q;
		        M.lanes |= m;
		        rh |= m;
		      }
		      l = l.next;
		    } while (null !== l && l !== f);
		    null === k ? g = d : k.next = h;
		    He(d, b.memoizedState) || (dh = !0);
		    b.memoizedState = d;
		    b.baseState = g;
		    b.baseQueue = k;
		    c.lastRenderedState = d;
		  }
		  a = c.interleaved;
		  if (null !== a) {
		    e = a;
		    do f = e.lane, M.lanes |= f, rh |= f, e = e.next; while (e !== a);
		  } else null === e && (c.lanes = 0);
		  return [b.memoizedState, c.dispatch];
		}
		function Xh(a) {
		  var b = Uh(),
		    c = b.queue;
		  if (null === c) throw Error(p(311));
		  c.lastRenderedReducer = a;
		  var d = c.dispatch,
		    e = c.pending,
		    f = b.memoizedState;
		  if (null !== e) {
		    c.pending = null;
		    var g = e = e.next;
		    do f = a(f, g.action), g = g.next; while (g !== e);
		    He(f, b.memoizedState) || (dh = !0);
		    b.memoizedState = f;
		    null === b.baseQueue && (b.baseState = f);
		    c.lastRenderedState = f;
		  }
		  return [f, d];
		}
		function Yh() {}
		function Zh(a, b) {
		  var c = M,
		    d = Uh(),
		    e = b(),
		    f = !He(d.memoizedState, e);
		  f && (d.memoizedState = e, dh = !0);
		  d = d.queue;
		  $h(ai.bind(null, c, d, a), [a]);
		  if (d.getSnapshot !== b || f || null !== O && O.memoizedState.tag & 1) {
		    c.flags |= 2048;
		    bi(9, ci.bind(null, c, d, e, b), void 0, null);
		    if (null === Q) throw Error(p(349));
		    0 !== (Hh & 30) || di(c, b, e);
		  }
		  return e;
		}
		function di(a, b, c) {
		  a.flags |= 16384;
		  a = {
		    getSnapshot: b,
		    value: c
		  };
		  b = M.updateQueue;
		  null === b ? (b = {
		    lastEffect: null,
		    stores: null
		  }, M.updateQueue = b, b.stores = [a]) : (c = b.stores, null === c ? b.stores = [a] : c.push(a));
		}
		function ci(a, b, c, d) {
		  b.value = c;
		  b.getSnapshot = d;
		  ei(b) && fi(a);
		}
		function ai(a, b, c) {
		  return c(function () {
		    ei(b) && fi(a);
		  });
		}
		function ei(a) {
		  var b = a.getSnapshot;
		  a = a.value;
		  try {
		    var c = b();
		    return !He(a, c);
		  } catch (d) {
		    return !0;
		  }
		}
		function fi(a) {
		  var b = ih(a, 1);
		  null !== b && gi(b, a, 1, -1);
		}
		function hi(a) {
		  var b = Th();
		  "function" === typeof a && (a = a());
		  b.memoizedState = b.baseState = a;
		  a = {
		    pending: null,
		    interleaved: null,
		    lanes: 0,
		    dispatch: null,
		    lastRenderedReducer: Vh,
		    lastRenderedState: a
		  };
		  b.queue = a;
		  a = a.dispatch = ii.bind(null, M, a);
		  return [b.memoizedState, a];
		}
		function bi(a, b, c, d) {
		  a = {
		    tag: a,
		    create: b,
		    destroy: c,
		    deps: d,
		    next: null
		  };
		  b = M.updateQueue;
		  null === b ? (b = {
		    lastEffect: null,
		    stores: null
		  }, M.updateQueue = b, b.lastEffect = a.next = a) : (c = b.lastEffect, null === c ? b.lastEffect = a.next = a : (d = c.next, c.next = a, a.next = d, b.lastEffect = a));
		  return a;
		}
		function ji() {
		  return Uh().memoizedState;
		}
		function ki(a, b, c, d) {
		  var e = Th();
		  M.flags |= a;
		  e.memoizedState = bi(1 | b, c, void 0, void 0 === d ? null : d);
		}
		function li(a, b, c, d) {
		  var e = Uh();
		  d = void 0 === d ? null : d;
		  var f = void 0;
		  if (null !== N) {
		    var g = N.memoizedState;
		    f = g.destroy;
		    if (null !== d && Mh(d, g.deps)) {
		      e.memoizedState = bi(b, c, f, d);
		      return;
		    }
		  }
		  M.flags |= a;
		  e.memoizedState = bi(1 | b, c, f, d);
		}
		function mi(a, b) {
		  return ki(8390656, 8, a, b);
		}
		function $h(a, b) {
		  return li(2048, 8, a, b);
		}
		function ni(a, b) {
		  return li(4, 2, a, b);
		}
		function oi(a, b) {
		  return li(4, 4, a, b);
		}
		function pi(a, b) {
		  if ("function" === typeof b) return a = a(), b(a), function () {
		    b(null);
		  };
		  if (null !== b && void 0 !== b) return a = a(), b.current = a, function () {
		    b.current = null;
		  };
		}
		function qi(a, b, c) {
		  c = null !== c && void 0 !== c ? c.concat([a]) : null;
		  return li(4, 4, pi.bind(null, b, a), c);
		}
		function ri() {}
		function si(a, b) {
		  var c = Uh();
		  b = void 0 === b ? null : b;
		  var d = c.memoizedState;
		  if (null !== d && null !== b && Mh(b, d[1])) return d[0];
		  c.memoizedState = [a, b];
		  return a;
		}
		function ti(a, b) {
		  var c = Uh();
		  b = void 0 === b ? null : b;
		  var d = c.memoizedState;
		  if (null !== d && null !== b && Mh(b, d[1])) return d[0];
		  a = a();
		  c.memoizedState = [a, b];
		  return a;
		}
		function ui(a, b, c) {
		  if (0 === (Hh & 21)) return a.baseState && (a.baseState = !1, dh = !0), a.memoizedState = c;
		  He(c, b) || (c = yc(), M.lanes |= c, rh |= c, a.baseState = !0);
		  return b;
		}
		function vi(a, b) {
		  var c = C;
		  C = 0 !== c && 4 > c ? c : 4;
		  a(!0);
		  var d = Gh.transition;
		  Gh.transition = {};
		  try {
		    a(!1), b();
		  } finally {
		    C = c, Gh.transition = d;
		  }
		}
		function wi() {
		  return Uh().memoizedState;
		}
		function xi(a, b, c) {
		  var d = yi(a);
		  c = {
		    lane: d,
		    action: c,
		    hasEagerState: !1,
		    eagerState: null,
		    next: null
		  };
		  if (zi(a)) Ai(b, c);else if (c = hh(a, b, c, d), null !== c) {
		    var e = R();
		    gi(c, a, d, e);
		    Bi(c, b, d);
		  }
		}
		function ii(a, b, c) {
		  var d = yi(a),
		    e = {
		      lane: d,
		      action: c,
		      hasEagerState: !1,
		      eagerState: null,
		      next: null
		    };
		  if (zi(a)) Ai(b, e);else {
		    var f = a.alternate;
		    if (0 === a.lanes && (null === f || 0 === f.lanes) && (f = b.lastRenderedReducer, null !== f)) try {
		      var g = b.lastRenderedState,
		        h = f(g, c);
		      e.hasEagerState = !0;
		      e.eagerState = h;
		      if (He(h, g)) {
		        var k = b.interleaved;
		        null === k ? (e.next = e, gh(b)) : (e.next = k.next, k.next = e);
		        b.interleaved = e;
		        return;
		      }
		    } catch (l) {} finally {}
		    c = hh(a, b, e, d);
		    null !== c && (e = R(), gi(c, a, d, e), Bi(c, b, d));
		  }
		}
		function zi(a) {
		  var b = a.alternate;
		  return a === M || null !== b && b === M;
		}
		function Ai(a, b) {
		  Jh = Ih = !0;
		  var c = a.pending;
		  null === c ? b.next = b : (b.next = c.next, c.next = b);
		  a.pending = b;
		}
		function Bi(a, b, c) {
		  if (0 !== (c & 4194240)) {
		    var d = b.lanes;
		    d &= a.pendingLanes;
		    c |= d;
		    b.lanes = c;
		    Cc(a, c);
		  }
		}
		var Rh = {
		    readContext: eh,
		    useCallback: P,
		    useContext: P,
		    useEffect: P,
		    useImperativeHandle: P,
		    useInsertionEffect: P,
		    useLayoutEffect: P,
		    useMemo: P,
		    useReducer: P,
		    useRef: P,
		    useState: P,
		    useDebugValue: P,
		    useDeferredValue: P,
		    useTransition: P,
		    useMutableSource: P,
		    useSyncExternalStore: P,
		    useId: P,
		    unstable_isNewReconciler: !1
		  },
		  Oh = {
		    readContext: eh,
		    useCallback: function (a, b) {
		      Th().memoizedState = [a, void 0 === b ? null : b];
		      return a;
		    },
		    useContext: eh,
		    useEffect: mi,
		    useImperativeHandle: function (a, b, c) {
		      c = null !== c && void 0 !== c ? c.concat([a]) : null;
		      return ki(4194308, 4, pi.bind(null, b, a), c);
		    },
		    useLayoutEffect: function (a, b) {
		      return ki(4194308, 4, a, b);
		    },
		    useInsertionEffect: function (a, b) {
		      return ki(4, 2, a, b);
		    },
		    useMemo: function (a, b) {
		      var c = Th();
		      b = void 0 === b ? null : b;
		      a = a();
		      c.memoizedState = [a, b];
		      return a;
		    },
		    useReducer: function (a, b, c) {
		      var d = Th();
		      b = void 0 !== c ? c(b) : b;
		      d.memoizedState = d.baseState = b;
		      a = {
		        pending: null,
		        interleaved: null,
		        lanes: 0,
		        dispatch: null,
		        lastRenderedReducer: a,
		        lastRenderedState: b
		      };
		      d.queue = a;
		      a = a.dispatch = xi.bind(null, M, a);
		      return [d.memoizedState, a];
		    },
		    useRef: function (a) {
		      var b = Th();
		      a = {
		        current: a
		      };
		      return b.memoizedState = a;
		    },
		    useState: hi,
		    useDebugValue: ri,
		    useDeferredValue: function (a) {
		      return Th().memoizedState = a;
		    },
		    useTransition: function () {
		      var a = hi(!1),
		        b = a[0];
		      a = vi.bind(null, a[1]);
		      Th().memoizedState = a;
		      return [b, a];
		    },
		    useMutableSource: function () {},
		    useSyncExternalStore: function (a, b, c) {
		      var d = M,
		        e = Th();
		      if (I) {
		        if (void 0 === c) throw Error(p(407));
		        c = c();
		      } else {
		        c = b();
		        if (null === Q) throw Error(p(349));
		        0 !== (Hh & 30) || di(d, b, c);
		      }
		      e.memoizedState = c;
		      var f = {
		        value: c,
		        getSnapshot: b
		      };
		      e.queue = f;
		      mi(ai.bind(null, d, f, a), [a]);
		      d.flags |= 2048;
		      bi(9, ci.bind(null, d, f, c, b), void 0, null);
		      return c;
		    },
		    useId: function () {
		      var a = Th(),
		        b = Q.identifierPrefix;
		      if (I) {
		        var c = sg;
		        var d = rg;
		        c = (d & ~(1 << 32 - oc(d) - 1)).toString(32) + c;
		        b = ":" + b + "R" + c;
		        c = Kh++;
		        0 < c && (b += "H" + c.toString(32));
		        b += ":";
		      } else c = Lh++, b = ":" + b + "r" + c.toString(32) + ":";
		      return a.memoizedState = b;
		    },
		    unstable_isNewReconciler: !1
		  },
		  Ph = {
		    readContext: eh,
		    useCallback: si,
		    useContext: eh,
		    useEffect: $h,
		    useImperativeHandle: qi,
		    useInsertionEffect: ni,
		    useLayoutEffect: oi,
		    useMemo: ti,
		    useReducer: Wh,
		    useRef: ji,
		    useState: function () {
		      return Wh(Vh);
		    },
		    useDebugValue: ri,
		    useDeferredValue: function (a) {
		      var b = Uh();
		      return ui(b, N.memoizedState, a);
		    },
		    useTransition: function () {
		      var a = Wh(Vh)[0],
		        b = Uh().memoizedState;
		      return [a, b];
		    },
		    useMutableSource: Yh,
		    useSyncExternalStore: Zh,
		    useId: wi,
		    unstable_isNewReconciler: !1
		  },
		  Qh = {
		    readContext: eh,
		    useCallback: si,
		    useContext: eh,
		    useEffect: $h,
		    useImperativeHandle: qi,
		    useInsertionEffect: ni,
		    useLayoutEffect: oi,
		    useMemo: ti,
		    useReducer: Xh,
		    useRef: ji,
		    useState: function () {
		      return Xh(Vh);
		    },
		    useDebugValue: ri,
		    useDeferredValue: function (a) {
		      var b = Uh();
		      return null === N ? b.memoizedState = a : ui(b, N.memoizedState, a);
		    },
		    useTransition: function () {
		      var a = Xh(Vh)[0],
		        b = Uh().memoizedState;
		      return [a, b];
		    },
		    useMutableSource: Yh,
		    useSyncExternalStore: Zh,
		    useId: wi,
		    unstable_isNewReconciler: !1
		  };
		function Ci(a, b) {
		  if (a && a.defaultProps) {
		    b = A({}, b);
		    a = a.defaultProps;
		    for (var c in a) void 0 === b[c] && (b[c] = a[c]);
		    return b;
		  }
		  return b;
		}
		function Di(a, b, c, d) {
		  b = a.memoizedState;
		  c = c(d, b);
		  c = null === c || void 0 === c ? b : A({}, b, c);
		  a.memoizedState = c;
		  0 === a.lanes && (a.updateQueue.baseState = c);
		}
		var Ei = {
		  isMounted: function (a) {
		    return (a = a._reactInternals) ? Vb(a) === a : !1;
		  },
		  enqueueSetState: function (a, b, c) {
		    a = a._reactInternals;
		    var d = R(),
		      e = yi(a),
		      f = mh(d, e);
		    f.payload = b;
		    void 0 !== c && null !== c && (f.callback = c);
		    b = nh(a, f, e);
		    null !== b && (gi(b, a, e, d), oh(b, a, e));
		  },
		  enqueueReplaceState: function (a, b, c) {
		    a = a._reactInternals;
		    var d = R(),
		      e = yi(a),
		      f = mh(d, e);
		    f.tag = 1;
		    f.payload = b;
		    void 0 !== c && null !== c && (f.callback = c);
		    b = nh(a, f, e);
		    null !== b && (gi(b, a, e, d), oh(b, a, e));
		  },
		  enqueueForceUpdate: function (a, b) {
		    a = a._reactInternals;
		    var c = R(),
		      d = yi(a),
		      e = mh(c, d);
		    e.tag = 2;
		    void 0 !== b && null !== b && (e.callback = b);
		    b = nh(a, e, d);
		    null !== b && (gi(b, a, d, c), oh(b, a, d));
		  }
		};
		function Fi(a, b, c, d, e, f, g) {
		  a = a.stateNode;
		  return "function" === typeof a.shouldComponentUpdate ? a.shouldComponentUpdate(d, f, g) : b.prototype && b.prototype.isPureReactComponent ? !Ie(c, d) || !Ie(e, f) : !0;
		}
		function Gi(a, b, c) {
		  var d = !1,
		    e = Vf;
		  var f = b.contextType;
		  "object" === typeof f && null !== f ? f = eh(f) : (e = Zf(b) ? Xf : H.current, d = b.contextTypes, f = (d = null !== d && void 0 !== d) ? Yf(a, e) : Vf);
		  b = new b(c, f);
		  a.memoizedState = null !== b.state && void 0 !== b.state ? b.state : null;
		  b.updater = Ei;
		  a.stateNode = b;
		  b._reactInternals = a;
		  d && (a = a.stateNode, a.__reactInternalMemoizedUnmaskedChildContext = e, a.__reactInternalMemoizedMaskedChildContext = f);
		  return b;
		}
		function Hi(a, b, c, d) {
		  a = b.state;
		  "function" === typeof b.componentWillReceiveProps && b.componentWillReceiveProps(c, d);
		  "function" === typeof b.UNSAFE_componentWillReceiveProps && b.UNSAFE_componentWillReceiveProps(c, d);
		  b.state !== a && Ei.enqueueReplaceState(b, b.state, null);
		}
		function Ii(a, b, c, d) {
		  var e = a.stateNode;
		  e.props = c;
		  e.state = a.memoizedState;
		  e.refs = {};
		  kh(a);
		  var f = b.contextType;
		  "object" === typeof f && null !== f ? e.context = eh(f) : (f = Zf(b) ? Xf : H.current, e.context = Yf(a, f));
		  e.state = a.memoizedState;
		  f = b.getDerivedStateFromProps;
		  "function" === typeof f && (Di(a, b, f, c), e.state = a.memoizedState);
		  "function" === typeof b.getDerivedStateFromProps || "function" === typeof e.getSnapshotBeforeUpdate || "function" !== typeof e.UNSAFE_componentWillMount && "function" !== typeof e.componentWillMount || (b = e.state, "function" === typeof e.componentWillMount && e.componentWillMount(), "function" === typeof e.UNSAFE_componentWillMount && e.UNSAFE_componentWillMount(), b !== e.state && Ei.enqueueReplaceState(e, e.state, null), qh(a, c, e, d), e.state = a.memoizedState);
		  "function" === typeof e.componentDidMount && (a.flags |= 4194308);
		}
		function Ji(a, b) {
		  try {
		    var c = "",
		      d = b;
		    do c += Pa(d), d = d.return; while (d);
		    var e = c;
		  } catch (f) {
		    e = "\nError generating stack: " + f.message + "\n" + f.stack;
		  }
		  return {
		    value: a,
		    source: b,
		    stack: e,
		    digest: null
		  };
		}
		function Ki(a, b, c) {
		  return {
		    value: a,
		    source: null,
		    stack: null != c ? c : null,
		    digest: null != b ? b : null
		  };
		}
		function Li(a, b) {
		  try {
		    console.error(b.value);
		  } catch (c) {
		    setTimeout(function () {
		      throw c;
		    });
		  }
		}
		var Mi = "function" === typeof WeakMap ? WeakMap : Map;
		function Ni(a, b, c) {
		  c = mh(-1, c);
		  c.tag = 3;
		  c.payload = {
		    element: null
		  };
		  var d = b.value;
		  c.callback = function () {
		    Oi || (Oi = !0, Pi = d);
		    Li(a, b);
		  };
		  return c;
		}
		function Qi(a, b, c) {
		  c = mh(-1, c);
		  c.tag = 3;
		  var d = a.type.getDerivedStateFromError;
		  if ("function" === typeof d) {
		    var e = b.value;
		    c.payload = function () {
		      return d(e);
		    };
		    c.callback = function () {
		      Li(a, b);
		    };
		  }
		  var f = a.stateNode;
		  null !== f && "function" === typeof f.componentDidCatch && (c.callback = function () {
		    Li(a, b);
		    "function" !== typeof d && (null === Ri ? Ri = new Set([this]) : Ri.add(this));
		    var c = b.stack;
		    this.componentDidCatch(b.value, {
		      componentStack: null !== c ? c : ""
		    });
		  });
		  return c;
		}
		function Si(a, b, c) {
		  var d = a.pingCache;
		  if (null === d) {
		    d = a.pingCache = new Mi();
		    var e = new Set();
		    d.set(b, e);
		  } else e = d.get(b), void 0 === e && (e = new Set(), d.set(b, e));
		  e.has(c) || (e.add(c), a = Ti.bind(null, a, b, c), b.then(a, a));
		}
		function Ui(a) {
		  do {
		    var b;
		    if (b = 13 === a.tag) b = a.memoizedState, b = null !== b ? null !== b.dehydrated ? !0 : !1 : !0;
		    if (b) return a;
		    a = a.return;
		  } while (null !== a);
		  return null;
		}
		function Vi(a, b, c, d, e) {
		  if (0 === (a.mode & 1)) return a === b ? a.flags |= 65536 : (a.flags |= 128, c.flags |= 131072, c.flags &= -52805, 1 === c.tag && (null === c.alternate ? c.tag = 17 : (b = mh(-1, 1), b.tag = 2, nh(c, b, 1))), c.lanes |= 1), a;
		  a.flags |= 65536;
		  a.lanes = e;
		  return a;
		}
		var Wi = ua.ReactCurrentOwner,
		  dh = !1;
		function Xi(a, b, c, d) {
		  b.child = null === a ? Vg(b, null, c, d) : Ug(b, a.child, c, d);
		}
		function Yi(a, b, c, d, e) {
		  c = c.render;
		  var f = b.ref;
		  ch(b, e);
		  d = Nh(a, b, c, d, f, e);
		  c = Sh();
		  if (null !== a && !dh) return b.updateQueue = a.updateQueue, b.flags &= -2053, a.lanes &= ~e, Zi(a, b, e);
		  I && c && vg(b);
		  b.flags |= 1;
		  Xi(a, b, d, e);
		  return b.child;
		}
		function $i(a, b, c, d, e) {
		  if (null === a) {
		    var f = c.type;
		    if ("function" === typeof f && !aj(f) && void 0 === f.defaultProps && null === c.compare && void 0 === c.defaultProps) return b.tag = 15, b.type = f, bj(a, b, f, d, e);
		    a = Rg(c.type, null, d, b, b.mode, e);
		    a.ref = b.ref;
		    a.return = b;
		    return b.child = a;
		  }
		  f = a.child;
		  if (0 === (a.lanes & e)) {
		    var g = f.memoizedProps;
		    c = c.compare;
		    c = null !== c ? c : Ie;
		    if (c(g, d) && a.ref === b.ref) return Zi(a, b, e);
		  }
		  b.flags |= 1;
		  a = Pg(f, d);
		  a.ref = b.ref;
		  a.return = b;
		  return b.child = a;
		}
		function bj(a, b, c, d, e) {
		  if (null !== a) {
		    var f = a.memoizedProps;
		    if (Ie(f, d) && a.ref === b.ref) if (dh = !1, b.pendingProps = d = f, 0 !== (a.lanes & e)) 0 !== (a.flags & 131072) && (dh = !0);else return b.lanes = a.lanes, Zi(a, b, e);
		  }
		  return cj(a, b, c, d, e);
		}
		function dj(a, b, c) {
		  var d = b.pendingProps,
		    e = d.children,
		    f = null !== a ? a.memoizedState : null;
		  if ("hidden" === d.mode) {
		    if (0 === (b.mode & 1)) b.memoizedState = {
		      baseLanes: 0,
		      cachePool: null,
		      transitions: null
		    }, G(ej, fj), fj |= c;else {
		      if (0 === (c & 1073741824)) return a = null !== f ? f.baseLanes | c : c, b.lanes = b.childLanes = 1073741824, b.memoizedState = {
		        baseLanes: a,
		        cachePool: null,
		        transitions: null
		      }, b.updateQueue = null, G(ej, fj), fj |= a, null;
		      b.memoizedState = {
		        baseLanes: 0,
		        cachePool: null,
		        transitions: null
		      };
		      d = null !== f ? f.baseLanes : c;
		      G(ej, fj);
		      fj |= d;
		    }
		  } else null !== f ? (d = f.baseLanes | c, b.memoizedState = null) : d = c, G(ej, fj), fj |= d;
		  Xi(a, b, e, c);
		  return b.child;
		}
		function gj(a, b) {
		  var c = b.ref;
		  if (null === a && null !== c || null !== a && a.ref !== c) b.flags |= 512, b.flags |= 2097152;
		}
		function cj(a, b, c, d, e) {
		  var f = Zf(c) ? Xf : H.current;
		  f = Yf(b, f);
		  ch(b, e);
		  c = Nh(a, b, c, d, f, e);
		  d = Sh();
		  if (null !== a && !dh) return b.updateQueue = a.updateQueue, b.flags &= -2053, a.lanes &= ~e, Zi(a, b, e);
		  I && d && vg(b);
		  b.flags |= 1;
		  Xi(a, b, c, e);
		  return b.child;
		}
		function hj(a, b, c, d, e) {
		  if (Zf(c)) {
		    var f = !0;
		    cg(b);
		  } else f = !1;
		  ch(b, e);
		  if (null === b.stateNode) ij(a, b), Gi(b, c, d), Ii(b, c, d, e), d = !0;else if (null === a) {
		    var g = b.stateNode,
		      h = b.memoizedProps;
		    g.props = h;
		    var k = g.context,
		      l = c.contextType;
		    "object" === typeof l && null !== l ? l = eh(l) : (l = Zf(c) ? Xf : H.current, l = Yf(b, l));
		    var m = c.getDerivedStateFromProps,
		      q = "function" === typeof m || "function" === typeof g.getSnapshotBeforeUpdate;
		    q || "function" !== typeof g.UNSAFE_componentWillReceiveProps && "function" !== typeof g.componentWillReceiveProps || (h !== d || k !== l) && Hi(b, g, d, l);
		    jh = !1;
		    var r = b.memoizedState;
		    g.state = r;
		    qh(b, d, g, e);
		    k = b.memoizedState;
		    h !== d || r !== k || Wf.current || jh ? ("function" === typeof m && (Di(b, c, m, d), k = b.memoizedState), (h = jh || Fi(b, c, h, d, r, k, l)) ? (q || "function" !== typeof g.UNSAFE_componentWillMount && "function" !== typeof g.componentWillMount || ("function" === typeof g.componentWillMount && g.componentWillMount(), "function" === typeof g.UNSAFE_componentWillMount && g.UNSAFE_componentWillMount()), "function" === typeof g.componentDidMount && (b.flags |= 4194308)) : ("function" === typeof g.componentDidMount && (b.flags |= 4194308), b.memoizedProps = d, b.memoizedState = k), g.props = d, g.state = k, g.context = l, d = h) : ("function" === typeof g.componentDidMount && (b.flags |= 4194308), d = !1);
		  } else {
		    g = b.stateNode;
		    lh(a, b);
		    h = b.memoizedProps;
		    l = b.type === b.elementType ? h : Ci(b.type, h);
		    g.props = l;
		    q = b.pendingProps;
		    r = g.context;
		    k = c.contextType;
		    "object" === typeof k && null !== k ? k = eh(k) : (k = Zf(c) ? Xf : H.current, k = Yf(b, k));
		    var y = c.getDerivedStateFromProps;
		    (m = "function" === typeof y || "function" === typeof g.getSnapshotBeforeUpdate) || "function" !== typeof g.UNSAFE_componentWillReceiveProps && "function" !== typeof g.componentWillReceiveProps || (h !== q || r !== k) && Hi(b, g, d, k);
		    jh = !1;
		    r = b.memoizedState;
		    g.state = r;
		    qh(b, d, g, e);
		    var n = b.memoizedState;
		    h !== q || r !== n || Wf.current || jh ? ("function" === typeof y && (Di(b, c, y, d), n = b.memoizedState), (l = jh || Fi(b, c, l, d, r, n, k) || !1) ? (m || "function" !== typeof g.UNSAFE_componentWillUpdate && "function" !== typeof g.componentWillUpdate || ("function" === typeof g.componentWillUpdate && g.componentWillUpdate(d, n, k), "function" === typeof g.UNSAFE_componentWillUpdate && g.UNSAFE_componentWillUpdate(d, n, k)), "function" === typeof g.componentDidUpdate && (b.flags |= 4), "function" === typeof g.getSnapshotBeforeUpdate && (b.flags |= 1024)) : ("function" !== typeof g.componentDidUpdate || h === a.memoizedProps && r === a.memoizedState || (b.flags |= 4), "function" !== typeof g.getSnapshotBeforeUpdate || h === a.memoizedProps && r === a.memoizedState || (b.flags |= 1024), b.memoizedProps = d, b.memoizedState = n), g.props = d, g.state = n, g.context = k, d = l) : ("function" !== typeof g.componentDidUpdate || h === a.memoizedProps && r === a.memoizedState || (b.flags |= 4), "function" !== typeof g.getSnapshotBeforeUpdate || h === a.memoizedProps && r === a.memoizedState || (b.flags |= 1024), d = !1);
		  }
		  return jj(a, b, c, d, f, e);
		}
		function jj(a, b, c, d, e, f) {
		  gj(a, b);
		  var g = 0 !== (b.flags & 128);
		  if (!d && !g) return e && dg(b, c, !1), Zi(a, b, f);
		  d = b.stateNode;
		  Wi.current = b;
		  var h = g && "function" !== typeof c.getDerivedStateFromError ? null : d.render();
		  b.flags |= 1;
		  null !== a && g ? (b.child = Ug(b, a.child, null, f), b.child = Ug(b, null, h, f)) : Xi(a, b, h, f);
		  b.memoizedState = d.state;
		  e && dg(b, c, !0);
		  return b.child;
		}
		function kj(a) {
		  var b = a.stateNode;
		  b.pendingContext ? ag(a, b.pendingContext, b.pendingContext !== b.context) : b.context && ag(a, b.context, !1);
		  yh(a, b.containerInfo);
		}
		function lj(a, b, c, d, e) {
		  Ig();
		  Jg(e);
		  b.flags |= 256;
		  Xi(a, b, c, d);
		  return b.child;
		}
		var mj = {
		  dehydrated: null,
		  treeContext: null,
		  retryLane: 0
		};
		function nj(a) {
		  return {
		    baseLanes: a,
		    cachePool: null,
		    transitions: null
		  };
		}
		function oj(a, b, c) {
		  var d = b.pendingProps,
		    e = L.current,
		    f = !1,
		    g = 0 !== (b.flags & 128),
		    h;
		  (h = g) || (h = null !== a && null === a.memoizedState ? !1 : 0 !== (e & 2));
		  if (h) f = !0, b.flags &= -129;else if (null === a || null !== a.memoizedState) e |= 1;
		  G(L, e & 1);
		  if (null === a) {
		    Eg(b);
		    a = b.memoizedState;
		    if (null !== a && (a = a.dehydrated, null !== a)) return 0 === (b.mode & 1) ? b.lanes = 1 : "$!" === a.data ? b.lanes = 8 : b.lanes = 1073741824, null;
		    g = d.children;
		    a = d.fallback;
		    return f ? (d = b.mode, f = b.child, g = {
		      mode: "hidden",
		      children: g
		    }, 0 === (d & 1) && null !== f ? (f.childLanes = 0, f.pendingProps = g) : f = pj(g, d, 0, null), a = Tg(a, d, c, null), f.return = b, a.return = b, f.sibling = a, b.child = f, b.child.memoizedState = nj(c), b.memoizedState = mj, a) : qj(b, g);
		  }
		  e = a.memoizedState;
		  if (null !== e && (h = e.dehydrated, null !== h)) return rj(a, b, g, d, h, e, c);
		  if (f) {
		    f = d.fallback;
		    g = b.mode;
		    e = a.child;
		    h = e.sibling;
		    var k = {
		      mode: "hidden",
		      children: d.children
		    };
		    0 === (g & 1) && b.child !== e ? (d = b.child, d.childLanes = 0, d.pendingProps = k, b.deletions = null) : (d = Pg(e, k), d.subtreeFlags = e.subtreeFlags & 14680064);
		    null !== h ? f = Pg(h, f) : (f = Tg(f, g, c, null), f.flags |= 2);
		    f.return = b;
		    d.return = b;
		    d.sibling = f;
		    b.child = d;
		    d = f;
		    f = b.child;
		    g = a.child.memoizedState;
		    g = null === g ? nj(c) : {
		      baseLanes: g.baseLanes | c,
		      cachePool: null,
		      transitions: g.transitions
		    };
		    f.memoizedState = g;
		    f.childLanes = a.childLanes & ~c;
		    b.memoizedState = mj;
		    return d;
		  }
		  f = a.child;
		  a = f.sibling;
		  d = Pg(f, {
		    mode: "visible",
		    children: d.children
		  });
		  0 === (b.mode & 1) && (d.lanes = c);
		  d.return = b;
		  d.sibling = null;
		  null !== a && (c = b.deletions, null === c ? (b.deletions = [a], b.flags |= 16) : c.push(a));
		  b.child = d;
		  b.memoizedState = null;
		  return d;
		}
		function qj(a, b) {
		  b = pj({
		    mode: "visible",
		    children: b
		  }, a.mode, 0, null);
		  b.return = a;
		  return a.child = b;
		}
		function sj(a, b, c, d) {
		  null !== d && Jg(d);
		  Ug(b, a.child, null, c);
		  a = qj(b, b.pendingProps.children);
		  a.flags |= 2;
		  b.memoizedState = null;
		  return a;
		}
		function rj(a, b, c, d, e, f, g) {
		  if (c) {
		    if (b.flags & 256) return b.flags &= -257, d = Ki(Error(p(422))), sj(a, b, g, d);
		    if (null !== b.memoizedState) return b.child = a.child, b.flags |= 128, null;
		    f = d.fallback;
		    e = b.mode;
		    d = pj({
		      mode: "visible",
		      children: d.children
		    }, e, 0, null);
		    f = Tg(f, e, g, null);
		    f.flags |= 2;
		    d.return = b;
		    f.return = b;
		    d.sibling = f;
		    b.child = d;
		    0 !== (b.mode & 1) && Ug(b, a.child, null, g);
		    b.child.memoizedState = nj(g);
		    b.memoizedState = mj;
		    return f;
		  }
		  if (0 === (b.mode & 1)) return sj(a, b, g, null);
		  if ("$!" === e.data) {
		    d = e.nextSibling && e.nextSibling.dataset;
		    if (d) var h = d.dgst;
		    d = h;
		    f = Error(p(419));
		    d = Ki(f, d, void 0);
		    return sj(a, b, g, d);
		  }
		  h = 0 !== (g & a.childLanes);
		  if (dh || h) {
		    d = Q;
		    if (null !== d) {
		      switch (g & -g) {
		        case 4:
		          e = 2;
		          break;
		        case 16:
		          e = 8;
		          break;
		        case 64:
		        case 128:
		        case 256:
		        case 512:
		        case 1024:
		        case 2048:
		        case 4096:
		        case 8192:
		        case 16384:
		        case 32768:
		        case 65536:
		        case 131072:
		        case 262144:
		        case 524288:
		        case 1048576:
		        case 2097152:
		        case 4194304:
		        case 8388608:
		        case 16777216:
		        case 33554432:
		        case 67108864:
		          e = 32;
		          break;
		        case 536870912:
		          e = 268435456;
		          break;
		        default:
		          e = 0;
		      }
		      e = 0 !== (e & (d.suspendedLanes | g)) ? 0 : e;
		      0 !== e && e !== f.retryLane && (f.retryLane = e, ih(a, e), gi(d, a, e, -1));
		    }
		    tj();
		    d = Ki(Error(p(421)));
		    return sj(a, b, g, d);
		  }
		  if ("$?" === e.data) return b.flags |= 128, b.child = a.child, b = uj.bind(null, a), e._reactRetry = b, null;
		  a = f.treeContext;
		  yg = Lf(e.nextSibling);
		  xg = b;
		  I = !0;
		  zg = null;
		  null !== a && (og[pg++] = rg, og[pg++] = sg, og[pg++] = qg, rg = a.id, sg = a.overflow, qg = b);
		  b = qj(b, d.children);
		  b.flags |= 4096;
		  return b;
		}
		function vj(a, b, c) {
		  a.lanes |= b;
		  var d = a.alternate;
		  null !== d && (d.lanes |= b);
		  bh(a.return, b, c);
		}
		function wj(a, b, c, d, e) {
		  var f = a.memoizedState;
		  null === f ? a.memoizedState = {
		    isBackwards: b,
		    rendering: null,
		    renderingStartTime: 0,
		    last: d,
		    tail: c,
		    tailMode: e
		  } : (f.isBackwards = b, f.rendering = null, f.renderingStartTime = 0, f.last = d, f.tail = c, f.tailMode = e);
		}
		function xj(a, b, c) {
		  var d = b.pendingProps,
		    e = d.revealOrder,
		    f = d.tail;
		  Xi(a, b, d.children, c);
		  d = L.current;
		  if (0 !== (d & 2)) d = d & 1 | 2, b.flags |= 128;else {
		    if (null !== a && 0 !== (a.flags & 128)) a: for (a = b.child; null !== a;) {
		      if (13 === a.tag) null !== a.memoizedState && vj(a, c, b);else if (19 === a.tag) vj(a, c, b);else if (null !== a.child) {
		        a.child.return = a;
		        a = a.child;
		        continue;
		      }
		      if (a === b) break a;
		      for (; null === a.sibling;) {
		        if (null === a.return || a.return === b) break a;
		        a = a.return;
		      }
		      a.sibling.return = a.return;
		      a = a.sibling;
		    }
		    d &= 1;
		  }
		  G(L, d);
		  if (0 === (b.mode & 1)) b.memoizedState = null;else switch (e) {
		    case "forwards":
		      c = b.child;
		      for (e = null; null !== c;) a = c.alternate, null !== a && null === Ch(a) && (e = c), c = c.sibling;
		      c = e;
		      null === c ? (e = b.child, b.child = null) : (e = c.sibling, c.sibling = null);
		      wj(b, !1, e, c, f);
		      break;
		    case "backwards":
		      c = null;
		      e = b.child;
		      for (b.child = null; null !== e;) {
		        a = e.alternate;
		        if (null !== a && null === Ch(a)) {
		          b.child = e;
		          break;
		        }
		        a = e.sibling;
		        e.sibling = c;
		        c = e;
		        e = a;
		      }
		      wj(b, !0, c, null, f);
		      break;
		    case "together":
		      wj(b, !1, null, null, void 0);
		      break;
		    default:
		      b.memoizedState = null;
		  }
		  return b.child;
		}
		function ij(a, b) {
		  0 === (b.mode & 1) && null !== a && (a.alternate = null, b.alternate = null, b.flags |= 2);
		}
		function Zi(a, b, c) {
		  null !== a && (b.dependencies = a.dependencies);
		  rh |= b.lanes;
		  if (0 === (c & b.childLanes)) return null;
		  if (null !== a && b.child !== a.child) throw Error(p(153));
		  if (null !== b.child) {
		    a = b.child;
		    c = Pg(a, a.pendingProps);
		    b.child = c;
		    for (c.return = b; null !== a.sibling;) a = a.sibling, c = c.sibling = Pg(a, a.pendingProps), c.return = b;
		    c.sibling = null;
		  }
		  return b.child;
		}
		function yj(a, b, c) {
		  switch (b.tag) {
		    case 3:
		      kj(b);
		      Ig();
		      break;
		    case 5:
		      Ah(b);
		      break;
		    case 1:
		      Zf(b.type) && cg(b);
		      break;
		    case 4:
		      yh(b, b.stateNode.containerInfo);
		      break;
		    case 10:
		      var d = b.type._context,
		        e = b.memoizedProps.value;
		      G(Wg, d._currentValue);
		      d._currentValue = e;
		      break;
		    case 13:
		      d = b.memoizedState;
		      if (null !== d) {
		        if (null !== d.dehydrated) return G(L, L.current & 1), b.flags |= 128, null;
		        if (0 !== (c & b.child.childLanes)) return oj(a, b, c);
		        G(L, L.current & 1);
		        a = Zi(a, b, c);
		        return null !== a ? a.sibling : null;
		      }
		      G(L, L.current & 1);
		      break;
		    case 19:
		      d = 0 !== (c & b.childLanes);
		      if (0 !== (a.flags & 128)) {
		        if (d) return xj(a, b, c);
		        b.flags |= 128;
		      }
		      e = b.memoizedState;
		      null !== e && (e.rendering = null, e.tail = null, e.lastEffect = null);
		      G(L, L.current);
		      if (d) break;else return null;
		    case 22:
		    case 23:
		      return b.lanes = 0, dj(a, b, c);
		  }
		  return Zi(a, b, c);
		}
		var zj, Aj, Bj, Cj;
		zj = function (a, b) {
		  for (var c = b.child; null !== c;) {
		    if (5 === c.tag || 6 === c.tag) a.appendChild(c.stateNode);else if (4 !== c.tag && null !== c.child) {
		      c.child.return = c;
		      c = c.child;
		      continue;
		    }
		    if (c === b) break;
		    for (; null === c.sibling;) {
		      if (null === c.return || c.return === b) return;
		      c = c.return;
		    }
		    c.sibling.return = c.return;
		    c = c.sibling;
		  }
		};
		Aj = function () {};
		Bj = function (a, b, c, d) {
		  var e = a.memoizedProps;
		  if (e !== d) {
		    a = b.stateNode;
		    xh(uh.current);
		    var f = null;
		    switch (c) {
		      case "input":
		        e = Ya(a, e);
		        d = Ya(a, d);
		        f = [];
		        break;
		      case "select":
		        e = A({}, e, {
		          value: void 0
		        });
		        d = A({}, d, {
		          value: void 0
		        });
		        f = [];
		        break;
		      case "textarea":
		        e = gb(a, e);
		        d = gb(a, d);
		        f = [];
		        break;
		      default:
		        "function" !== typeof e.onClick && "function" === typeof d.onClick && (a.onclick = Bf);
		    }
		    ub(c, d);
		    var g;
		    c = null;
		    for (l in e) if (!d.hasOwnProperty(l) && e.hasOwnProperty(l) && null != e[l]) if ("style" === l) {
		      var h = e[l];
		      for (g in h) h.hasOwnProperty(g) && (c || (c = {}), c[g] = "");
		    } else "dangerouslySetInnerHTML" !== l && "children" !== l && "suppressContentEditableWarning" !== l && "suppressHydrationWarning" !== l && "autoFocus" !== l && (ea.hasOwnProperty(l) ? f || (f = []) : (f = f || []).push(l, null));
		    for (l in d) {
		      var k = d[l];
		      h = null != e ? e[l] : void 0;
		      if (d.hasOwnProperty(l) && k !== h && (null != k || null != h)) if ("style" === l) {
		        if (h) {
		          for (g in h) !h.hasOwnProperty(g) || k && k.hasOwnProperty(g) || (c || (c = {}), c[g] = "");
		          for (g in k) k.hasOwnProperty(g) && h[g] !== k[g] && (c || (c = {}), c[g] = k[g]);
		        } else c || (f || (f = []), f.push(l, c)), c = k;
		      } else "dangerouslySetInnerHTML" === l ? (k = k ? k.__html : void 0, h = h ? h.__html : void 0, null != k && h !== k && (f = f || []).push(l, k)) : "children" === l ? "string" !== typeof k && "number" !== typeof k || (f = f || []).push(l, "" + k) : "suppressContentEditableWarning" !== l && "suppressHydrationWarning" !== l && (ea.hasOwnProperty(l) ? (null != k && "onScroll" === l && D("scroll", a), f || h === k || (f = [])) : (f = f || []).push(l, k));
		    }
		    c && (f = f || []).push("style", c);
		    var l = f;
		    if (b.updateQueue = l) b.flags |= 4;
		  }
		};
		Cj = function (a, b, c, d) {
		  c !== d && (b.flags |= 4);
		};
		function Dj(a, b) {
		  if (!I) switch (a.tailMode) {
		    case "hidden":
		      b = a.tail;
		      for (var c = null; null !== b;) null !== b.alternate && (c = b), b = b.sibling;
		      null === c ? a.tail = null : c.sibling = null;
		      break;
		    case "collapsed":
		      c = a.tail;
		      for (var d = null; null !== c;) null !== c.alternate && (d = c), c = c.sibling;
		      null === d ? b || null === a.tail ? a.tail = null : a.tail.sibling = null : d.sibling = null;
		  }
		}
		function S(a) {
		  var b = null !== a.alternate && a.alternate.child === a.child,
		    c = 0,
		    d = 0;
		  if (b) for (var e = a.child; null !== e;) c |= e.lanes | e.childLanes, d |= e.subtreeFlags & 14680064, d |= e.flags & 14680064, e.return = a, e = e.sibling;else for (e = a.child; null !== e;) c |= e.lanes | e.childLanes, d |= e.subtreeFlags, d |= e.flags, e.return = a, e = e.sibling;
		  a.subtreeFlags |= d;
		  a.childLanes = c;
		  return b;
		}
		function Ej(a, b, c) {
		  var d = b.pendingProps;
		  wg(b);
		  switch (b.tag) {
		    case 2:
		    case 16:
		    case 15:
		    case 0:
		    case 11:
		    case 7:
		    case 8:
		    case 12:
		    case 9:
		    case 14:
		      return S(b), null;
		    case 1:
		      return Zf(b.type) && $f(), S(b), null;
		    case 3:
		      d = b.stateNode;
		      zh();
		      E(Wf);
		      E(H);
		      Eh();
		      d.pendingContext && (d.context = d.pendingContext, d.pendingContext = null);
		      if (null === a || null === a.child) Gg(b) ? b.flags |= 4 : null === a || a.memoizedState.isDehydrated && 0 === (b.flags & 256) || (b.flags |= 1024, null !== zg && (Fj(zg), zg = null));
		      Aj(a, b);
		      S(b);
		      return null;
		    case 5:
		      Bh(b);
		      var e = xh(wh.current);
		      c = b.type;
		      if (null !== a && null != b.stateNode) Bj(a, b, c, d, e), a.ref !== b.ref && (b.flags |= 512, b.flags |= 2097152);else {
		        if (!d) {
		          if (null === b.stateNode) throw Error(p(166));
		          S(b);
		          return null;
		        }
		        a = xh(uh.current);
		        if (Gg(b)) {
		          d = b.stateNode;
		          c = b.type;
		          var f = b.memoizedProps;
		          d[Of] = b;
		          d[Pf] = f;
		          a = 0 !== (b.mode & 1);
		          switch (c) {
		            case "dialog":
		              D("cancel", d);
		              D("close", d);
		              break;
		            case "iframe":
		            case "object":
		            case "embed":
		              D("load", d);
		              break;
		            case "video":
		            case "audio":
		              for (e = 0; e < lf.length; e++) D(lf[e], d);
		              break;
		            case "source":
		              D("error", d);
		              break;
		            case "img":
		            case "image":
		            case "link":
		              D("error", d);
		              D("load", d);
		              break;
		            case "details":
		              D("toggle", d);
		              break;
		            case "input":
		              Za(d, f);
		              D("invalid", d);
		              break;
		            case "select":
		              d._wrapperState = {
		                wasMultiple: !!f.multiple
		              };
		              D("invalid", d);
		              break;
		            case "textarea":
		              hb(d, f), D("invalid", d);
		          }
		          ub(c, f);
		          e = null;
		          for (var g in f) if (f.hasOwnProperty(g)) {
		            var h = f[g];
		            "children" === g ? "string" === typeof h ? d.textContent !== h && (!0 !== f.suppressHydrationWarning && Af(d.textContent, h, a), e = ["children", h]) : "number" === typeof h && d.textContent !== "" + h && (!0 !== f.suppressHydrationWarning && Af(d.textContent, h, a), e = ["children", "" + h]) : ea.hasOwnProperty(g) && null != h && "onScroll" === g && D("scroll", d);
		          }
		          switch (c) {
		            case "input":
		              Va(d);
		              db(d, f, !0);
		              break;
		            case "textarea":
		              Va(d);
		              jb(d);
		              break;
		            case "select":
		            case "option":
		              break;
		            default:
		              "function" === typeof f.onClick && (d.onclick = Bf);
		          }
		          d = e;
		          b.updateQueue = d;
		          null !== d && (b.flags |= 4);
		        } else {
		          g = 9 === e.nodeType ? e : e.ownerDocument;
		          "http://www.w3.org/1999/xhtml" === a && (a = kb(c));
		          "http://www.w3.org/1999/xhtml" === a ? "script" === c ? (a = g.createElement("div"), a.innerHTML = "<script>\x3c/script>", a = a.removeChild(a.firstChild)) : "string" === typeof d.is ? a = g.createElement(c, {
		            is: d.is
		          }) : (a = g.createElement(c), "select" === c && (g = a, d.multiple ? g.multiple = !0 : d.size && (g.size = d.size))) : a = g.createElementNS(a, c);
		          a[Of] = b;
		          a[Pf] = d;
		          zj(a, b, !1, !1);
		          b.stateNode = a;
		          a: {
		            g = vb(c, d);
		            switch (c) {
		              case "dialog":
		                D("cancel", a);
		                D("close", a);
		                e = d;
		                break;
		              case "iframe":
		              case "object":
		              case "embed":
		                D("load", a);
		                e = d;
		                break;
		              case "video":
		              case "audio":
		                for (e = 0; e < lf.length; e++) D(lf[e], a);
		                e = d;
		                break;
		              case "source":
		                D("error", a);
		                e = d;
		                break;
		              case "img":
		              case "image":
		              case "link":
		                D("error", a);
		                D("load", a);
		                e = d;
		                break;
		              case "details":
		                D("toggle", a);
		                e = d;
		                break;
		              case "input":
		                Za(a, d);
		                e = Ya(a, d);
		                D("invalid", a);
		                break;
		              case "option":
		                e = d;
		                break;
		              case "select":
		                a._wrapperState = {
		                  wasMultiple: !!d.multiple
		                };
		                e = A({}, d, {
		                  value: void 0
		                });
		                D("invalid", a);
		                break;
		              case "textarea":
		                hb(a, d);
		                e = gb(a, d);
		                D("invalid", a);
		                break;
		              default:
		                e = d;
		            }
		            ub(c, e);
		            h = e;
		            for (f in h) if (h.hasOwnProperty(f)) {
		              var k = h[f];
		              "style" === f ? sb(a, k) : "dangerouslySetInnerHTML" === f ? (k = k ? k.__html : void 0, null != k && nb(a, k)) : "children" === f ? "string" === typeof k ? ("textarea" !== c || "" !== k) && ob(a, k) : "number" === typeof k && ob(a, "" + k) : "suppressContentEditableWarning" !== f && "suppressHydrationWarning" !== f && "autoFocus" !== f && (ea.hasOwnProperty(f) ? null != k && "onScroll" === f && D("scroll", a) : null != k && ta(a, f, k, g));
		            }
		            switch (c) {
		              case "input":
		                Va(a);
		                db(a, d, !1);
		                break;
		              case "textarea":
		                Va(a);
		                jb(a);
		                break;
		              case "option":
		                null != d.value && a.setAttribute("value", "" + Sa(d.value));
		                break;
		              case "select":
		                a.multiple = !!d.multiple;
		                f = d.value;
		                null != f ? fb(a, !!d.multiple, f, !1) : null != d.defaultValue && fb(a, !!d.multiple, d.defaultValue, !0);
		                break;
		              default:
		                "function" === typeof e.onClick && (a.onclick = Bf);
		            }
		            switch (c) {
		              case "button":
		              case "input":
		              case "select":
		              case "textarea":
		                d = !!d.autoFocus;
		                break a;
		              case "img":
		                d = !0;
		                break a;
		              default:
		                d = !1;
		            }
		          }
		          d && (b.flags |= 4);
		        }
		        null !== b.ref && (b.flags |= 512, b.flags |= 2097152);
		      }
		      S(b);
		      return null;
		    case 6:
		      if (a && null != b.stateNode) Cj(a, b, a.memoizedProps, d);else {
		        if ("string" !== typeof d && null === b.stateNode) throw Error(p(166));
		        c = xh(wh.current);
		        xh(uh.current);
		        if (Gg(b)) {
		          d = b.stateNode;
		          c = b.memoizedProps;
		          d[Of] = b;
		          if (f = d.nodeValue !== c) if (a = xg, null !== a) switch (a.tag) {
		            case 3:
		              Af(d.nodeValue, c, 0 !== (a.mode & 1));
		              break;
		            case 5:
		              !0 !== a.memoizedProps.suppressHydrationWarning && Af(d.nodeValue, c, 0 !== (a.mode & 1));
		          }
		          f && (b.flags |= 4);
		        } else d = (9 === c.nodeType ? c : c.ownerDocument).createTextNode(d), d[Of] = b, b.stateNode = d;
		      }
		      S(b);
		      return null;
		    case 13:
		      E(L);
		      d = b.memoizedState;
		      if (null === a || null !== a.memoizedState && null !== a.memoizedState.dehydrated) {
		        if (I && null !== yg && 0 !== (b.mode & 1) && 0 === (b.flags & 128)) Hg(), Ig(), b.flags |= 98560, f = !1;else if (f = Gg(b), null !== d && null !== d.dehydrated) {
		          if (null === a) {
		            if (!f) throw Error(p(318));
		            f = b.memoizedState;
		            f = null !== f ? f.dehydrated : null;
		            if (!f) throw Error(p(317));
		            f[Of] = b;
		          } else Ig(), 0 === (b.flags & 128) && (b.memoizedState = null), b.flags |= 4;
		          S(b);
		          f = !1;
		        } else null !== zg && (Fj(zg), zg = null), f = !0;
		        if (!f) return b.flags & 65536 ? b : null;
		      }
		      if (0 !== (b.flags & 128)) return b.lanes = c, b;
		      d = null !== d;
		      d !== (null !== a && null !== a.memoizedState) && d && (b.child.flags |= 8192, 0 !== (b.mode & 1) && (null === a || 0 !== (L.current & 1) ? 0 === T && (T = 3) : tj()));
		      null !== b.updateQueue && (b.flags |= 4);
		      S(b);
		      return null;
		    case 4:
		      return zh(), Aj(a, b), null === a && sf(b.stateNode.containerInfo), S(b), null;
		    case 10:
		      return ah(b.type._context), S(b), null;
		    case 17:
		      return Zf(b.type) && $f(), S(b), null;
		    case 19:
		      E(L);
		      f = b.memoizedState;
		      if (null === f) return S(b), null;
		      d = 0 !== (b.flags & 128);
		      g = f.rendering;
		      if (null === g) {
		        if (d) Dj(f, !1);else {
		          if (0 !== T || null !== a && 0 !== (a.flags & 128)) for (a = b.child; null !== a;) {
		            g = Ch(a);
		            if (null !== g) {
		              b.flags |= 128;
		              Dj(f, !1);
		              d = g.updateQueue;
		              null !== d && (b.updateQueue = d, b.flags |= 4);
		              b.subtreeFlags = 0;
		              d = c;
		              for (c = b.child; null !== c;) f = c, a = d, f.flags &= 14680066, g = f.alternate, null === g ? (f.childLanes = 0, f.lanes = a, f.child = null, f.subtreeFlags = 0, f.memoizedProps = null, f.memoizedState = null, f.updateQueue = null, f.dependencies = null, f.stateNode = null) : (f.childLanes = g.childLanes, f.lanes = g.lanes, f.child = g.child, f.subtreeFlags = 0, f.deletions = null, f.memoizedProps = g.memoizedProps, f.memoizedState = g.memoizedState, f.updateQueue = g.updateQueue, f.type = g.type, a = g.dependencies, f.dependencies = null === a ? null : {
		                lanes: a.lanes,
		                firstContext: a.firstContext
		              }), c = c.sibling;
		              G(L, L.current & 1 | 2);
		              return b.child;
		            }
		            a = a.sibling;
		          }
		          null !== f.tail && B() > Gj && (b.flags |= 128, d = !0, Dj(f, !1), b.lanes = 4194304);
		        }
		      } else {
		        if (!d) if (a = Ch(g), null !== a) {
		          if (b.flags |= 128, d = !0, c = a.updateQueue, null !== c && (b.updateQueue = c, b.flags |= 4), Dj(f, !0), null === f.tail && "hidden" === f.tailMode && !g.alternate && !I) return S(b), null;
		        } else 2 * B() - f.renderingStartTime > Gj && 1073741824 !== c && (b.flags |= 128, d = !0, Dj(f, !1), b.lanes = 4194304);
		        f.isBackwards ? (g.sibling = b.child, b.child = g) : (c = f.last, null !== c ? c.sibling = g : b.child = g, f.last = g);
		      }
		      if (null !== f.tail) return b = f.tail, f.rendering = b, f.tail = b.sibling, f.renderingStartTime = B(), b.sibling = null, c = L.current, G(L, d ? c & 1 | 2 : c & 1), b;
		      S(b);
		      return null;
		    case 22:
		    case 23:
		      return Hj(), d = null !== b.memoizedState, null !== a && null !== a.memoizedState !== d && (b.flags |= 8192), d && 0 !== (b.mode & 1) ? 0 !== (fj & 1073741824) && (S(b), b.subtreeFlags & 6 && (b.flags |= 8192)) : S(b), null;
		    case 24:
		      return null;
		    case 25:
		      return null;
		  }
		  throw Error(p(156, b.tag));
		}
		function Ij(a, b) {
		  wg(b);
		  switch (b.tag) {
		    case 1:
		      return Zf(b.type) && $f(), a = b.flags, a & 65536 ? (b.flags = a & -65537 | 128, b) : null;
		    case 3:
		      return zh(), E(Wf), E(H), Eh(), a = b.flags, 0 !== (a & 65536) && 0 === (a & 128) ? (b.flags = a & -65537 | 128, b) : null;
		    case 5:
		      return Bh(b), null;
		    case 13:
		      E(L);
		      a = b.memoizedState;
		      if (null !== a && null !== a.dehydrated) {
		        if (null === b.alternate) throw Error(p(340));
		        Ig();
		      }
		      a = b.flags;
		      return a & 65536 ? (b.flags = a & -65537 | 128, b) : null;
		    case 19:
		      return E(L), null;
		    case 4:
		      return zh(), null;
		    case 10:
		      return ah(b.type._context), null;
		    case 22:
		    case 23:
		      return Hj(), null;
		    case 24:
		      return null;
		    default:
		      return null;
		  }
		}
		var Jj = !1,
		  U = !1,
		  Kj = "function" === typeof WeakSet ? WeakSet : Set,
		  V = null;
		function Lj(a, b) {
		  var c = a.ref;
		  if (null !== c) if ("function" === typeof c) try {
		    c(null);
		  } catch (d) {
		    W(a, b, d);
		  } else c.current = null;
		}
		function Mj(a, b, c) {
		  try {
		    c();
		  } catch (d) {
		    W(a, b, d);
		  }
		}
		var Nj = !1;
		function Oj(a, b) {
		  Cf = dd;
		  a = Me();
		  if (Ne(a)) {
		    if ("selectionStart" in a) var c = {
		      start: a.selectionStart,
		      end: a.selectionEnd
		    };else a: {
		      c = (c = a.ownerDocument) && c.defaultView || window;
		      var d = c.getSelection && c.getSelection();
		      if (d && 0 !== d.rangeCount) {
		        c = d.anchorNode;
		        var e = d.anchorOffset,
		          f = d.focusNode;
		        d = d.focusOffset;
		        try {
		          c.nodeType, f.nodeType;
		        } catch (F) {
		          c = null;
		          break a;
		        }
		        var g = 0,
		          h = -1,
		          k = -1,
		          l = 0,
		          m = 0,
		          q = a,
		          r = null;
		        b: for (;;) {
		          for (var y;;) {
		            q !== c || 0 !== e && 3 !== q.nodeType || (h = g + e);
		            q !== f || 0 !== d && 3 !== q.nodeType || (k = g + d);
		            3 === q.nodeType && (g += q.nodeValue.length);
		            if (null === (y = q.firstChild)) break;
		            r = q;
		            q = y;
		          }
		          for (;;) {
		            if (q === a) break b;
		            r === c && ++l === e && (h = g);
		            r === f && ++m === d && (k = g);
		            if (null !== (y = q.nextSibling)) break;
		            q = r;
		            r = q.parentNode;
		          }
		          q = y;
		        }
		        c = -1 === h || -1 === k ? null : {
		          start: h,
		          end: k
		        };
		      } else c = null;
		    }
		    c = c || {
		      start: 0,
		      end: 0
		    };
		  } else c = null;
		  Df = {
		    focusedElem: a,
		    selectionRange: c
		  };
		  dd = !1;
		  for (V = b; null !== V;) if (b = V, a = b.child, 0 !== (b.subtreeFlags & 1028) && null !== a) a.return = b, V = a;else for (; null !== V;) {
		    b = V;
		    try {
		      var n = b.alternate;
		      if (0 !== (b.flags & 1024)) switch (b.tag) {
		        case 0:
		        case 11:
		        case 15:
		          break;
		        case 1:
		          if (null !== n) {
		            var t = n.memoizedProps,
		              J = n.memoizedState,
		              x = b.stateNode,
		              w = x.getSnapshotBeforeUpdate(b.elementType === b.type ? t : Ci(b.type, t), J);
		            x.__reactInternalSnapshotBeforeUpdate = w;
		          }
		          break;
		        case 3:
		          var u = b.stateNode.containerInfo;
		          1 === u.nodeType ? u.textContent = "" : 9 === u.nodeType && u.documentElement && u.removeChild(u.documentElement);
		          break;
		        case 5:
		        case 6:
		        case 4:
		        case 17:
		          break;
		        default:
		          throw Error(p(163));
		      }
		    } catch (F) {
		      W(b, b.return, F);
		    }
		    a = b.sibling;
		    if (null !== a) {
		      a.return = b.return;
		      V = a;
		      break;
		    }
		    V = b.return;
		  }
		  n = Nj;
		  Nj = !1;
		  return n;
		}
		function Pj(a, b, c) {
		  var d = b.updateQueue;
		  d = null !== d ? d.lastEffect : null;
		  if (null !== d) {
		    var e = d = d.next;
		    do {
		      if ((e.tag & a) === a) {
		        var f = e.destroy;
		        e.destroy = void 0;
		        void 0 !== f && Mj(b, c, f);
		      }
		      e = e.next;
		    } while (e !== d);
		  }
		}
		function Qj(a, b) {
		  b = b.updateQueue;
		  b = null !== b ? b.lastEffect : null;
		  if (null !== b) {
		    var c = b = b.next;
		    do {
		      if ((c.tag & a) === a) {
		        var d = c.create;
		        c.destroy = d();
		      }
		      c = c.next;
		    } while (c !== b);
		  }
		}
		function Rj(a) {
		  var b = a.ref;
		  if (null !== b) {
		    var c = a.stateNode;
		    switch (a.tag) {
		      case 5:
		        a = c;
		        break;
		      default:
		        a = c;
		    }
		    "function" === typeof b ? b(a) : b.current = a;
		  }
		}
		function Sj(a) {
		  var b = a.alternate;
		  null !== b && (a.alternate = null, Sj(b));
		  a.child = null;
		  a.deletions = null;
		  a.sibling = null;
		  5 === a.tag && (b = a.stateNode, null !== b && (delete b[Of], delete b[Pf], delete b[of], delete b[Qf], delete b[Rf]));
		  a.stateNode = null;
		  a.return = null;
		  a.dependencies = null;
		  a.memoizedProps = null;
		  a.memoizedState = null;
		  a.pendingProps = null;
		  a.stateNode = null;
		  a.updateQueue = null;
		}
		function Tj(a) {
		  return 5 === a.tag || 3 === a.tag || 4 === a.tag;
		}
		function Uj(a) {
		  a: for (;;) {
		    for (; null === a.sibling;) {
		      if (null === a.return || Tj(a.return)) return null;
		      a = a.return;
		    }
		    a.sibling.return = a.return;
		    for (a = a.sibling; 5 !== a.tag && 6 !== a.tag && 18 !== a.tag;) {
		      if (a.flags & 2) continue a;
		      if (null === a.child || 4 === a.tag) continue a;else a.child.return = a, a = a.child;
		    }
		    if (!(a.flags & 2)) return a.stateNode;
		  }
		}
		function Vj(a, b, c) {
		  var d = a.tag;
		  if (5 === d || 6 === d) a = a.stateNode, b ? 8 === c.nodeType ? c.parentNode.insertBefore(a, b) : c.insertBefore(a, b) : (8 === c.nodeType ? (b = c.parentNode, b.insertBefore(a, c)) : (b = c, b.appendChild(a)), c = c._reactRootContainer, null !== c && void 0 !== c || null !== b.onclick || (b.onclick = Bf));else if (4 !== d && (a = a.child, null !== a)) for (Vj(a, b, c), a = a.sibling; null !== a;) Vj(a, b, c), a = a.sibling;
		}
		function Wj(a, b, c) {
		  var d = a.tag;
		  if (5 === d || 6 === d) a = a.stateNode, b ? c.insertBefore(a, b) : c.appendChild(a);else if (4 !== d && (a = a.child, null !== a)) for (Wj(a, b, c), a = a.sibling; null !== a;) Wj(a, b, c), a = a.sibling;
		}
		var X = null,
		  Xj = !1;
		function Yj(a, b, c) {
		  for (c = c.child; null !== c;) Zj(a, b, c), c = c.sibling;
		}
		function Zj(a, b, c) {
		  if (lc && "function" === typeof lc.onCommitFiberUnmount) try {
		    lc.onCommitFiberUnmount(kc, c);
		  } catch (h) {}
		  switch (c.tag) {
		    case 5:
		      U || Lj(c, b);
		    case 6:
		      var d = X,
		        e = Xj;
		      X = null;
		      Yj(a, b, c);
		      X = d;
		      Xj = e;
		      null !== X && (Xj ? (a = X, c = c.stateNode, 8 === a.nodeType ? a.parentNode.removeChild(c) : a.removeChild(c)) : X.removeChild(c.stateNode));
		      break;
		    case 18:
		      null !== X && (Xj ? (a = X, c = c.stateNode, 8 === a.nodeType ? Kf(a.parentNode, c) : 1 === a.nodeType && Kf(a, c), bd(a)) : Kf(X, c.stateNode));
		      break;
		    case 4:
		      d = X;
		      e = Xj;
		      X = c.stateNode.containerInfo;
		      Xj = !0;
		      Yj(a, b, c);
		      X = d;
		      Xj = e;
		      break;
		    case 0:
		    case 11:
		    case 14:
		    case 15:
		      if (!U && (d = c.updateQueue, null !== d && (d = d.lastEffect, null !== d))) {
		        e = d = d.next;
		        do {
		          var f = e,
		            g = f.destroy;
		          f = f.tag;
		          void 0 !== g && (0 !== (f & 2) ? Mj(c, b, g) : 0 !== (f & 4) && Mj(c, b, g));
		          e = e.next;
		        } while (e !== d);
		      }
		      Yj(a, b, c);
		      break;
		    case 1:
		      if (!U && (Lj(c, b), d = c.stateNode, "function" === typeof d.componentWillUnmount)) try {
		        d.props = c.memoizedProps, d.state = c.memoizedState, d.componentWillUnmount();
		      } catch (h) {
		        W(c, b, h);
		      }
		      Yj(a, b, c);
		      break;
		    case 21:
		      Yj(a, b, c);
		      break;
		    case 22:
		      c.mode & 1 ? (U = (d = U) || null !== c.memoizedState, Yj(a, b, c), U = d) : Yj(a, b, c);
		      break;
		    default:
		      Yj(a, b, c);
		  }
		}
		function ak(a) {
		  var b = a.updateQueue;
		  if (null !== b) {
		    a.updateQueue = null;
		    var c = a.stateNode;
		    null === c && (c = a.stateNode = new Kj());
		    b.forEach(function (b) {
		      var d = bk.bind(null, a, b);
		      c.has(b) || (c.add(b), b.then(d, d));
		    });
		  }
		}
		function ck(a, b) {
		  var c = b.deletions;
		  if (null !== c) for (var d = 0; d < c.length; d++) {
		    var e = c[d];
		    try {
		      var f = a,
		        g = b,
		        h = g;
		      a: for (; null !== h;) {
		        switch (h.tag) {
		          case 5:
		            X = h.stateNode;
		            Xj = !1;
		            break a;
		          case 3:
		            X = h.stateNode.containerInfo;
		            Xj = !0;
		            break a;
		          case 4:
		            X = h.stateNode.containerInfo;
		            Xj = !0;
		            break a;
		        }
		        h = h.return;
		      }
		      if (null === X) throw Error(p(160));
		      Zj(f, g, e);
		      X = null;
		      Xj = !1;
		      var k = e.alternate;
		      null !== k && (k.return = null);
		      e.return = null;
		    } catch (l) {
		      W(e, b, l);
		    }
		  }
		  if (b.subtreeFlags & 12854) for (b = b.child; null !== b;) dk(b, a), b = b.sibling;
		}
		function dk(a, b) {
		  var c = a.alternate,
		    d = a.flags;
		  switch (a.tag) {
		    case 0:
		    case 11:
		    case 14:
		    case 15:
		      ck(b, a);
		      ek(a);
		      if (d & 4) {
		        try {
		          Pj(3, a, a.return), Qj(3, a);
		        } catch (t) {
		          W(a, a.return, t);
		        }
		        try {
		          Pj(5, a, a.return);
		        } catch (t) {
		          W(a, a.return, t);
		        }
		      }
		      break;
		    case 1:
		      ck(b, a);
		      ek(a);
		      d & 512 && null !== c && Lj(c, c.return);
		      break;
		    case 5:
		      ck(b, a);
		      ek(a);
		      d & 512 && null !== c && Lj(c, c.return);
		      if (a.flags & 32) {
		        var e = a.stateNode;
		        try {
		          ob(e, "");
		        } catch (t) {
		          W(a, a.return, t);
		        }
		      }
		      if (d & 4 && (e = a.stateNode, null != e)) {
		        var f = a.memoizedProps,
		          g = null !== c ? c.memoizedProps : f,
		          h = a.type,
		          k = a.updateQueue;
		        a.updateQueue = null;
		        if (null !== k) try {
		          "input" === h && "radio" === f.type && null != f.name && ab(e, f);
		          vb(h, g);
		          var l = vb(h, f);
		          for (g = 0; g < k.length; g += 2) {
		            var m = k[g],
		              q = k[g + 1];
		            "style" === m ? sb(e, q) : "dangerouslySetInnerHTML" === m ? nb(e, q) : "children" === m ? ob(e, q) : ta(e, m, q, l);
		          }
		          switch (h) {
		            case "input":
		              bb(e, f);
		              break;
		            case "textarea":
		              ib(e, f);
		              break;
		            case "select":
		              var r = e._wrapperState.wasMultiple;
		              e._wrapperState.wasMultiple = !!f.multiple;
		              var y = f.value;
		              null != y ? fb(e, !!f.multiple, y, !1) : r !== !!f.multiple && (null != f.defaultValue ? fb(e, !!f.multiple, f.defaultValue, !0) : fb(e, !!f.multiple, f.multiple ? [] : "", !1));
		          }
		          e[Pf] = f;
		        } catch (t) {
		          W(a, a.return, t);
		        }
		      }
		      break;
		    case 6:
		      ck(b, a);
		      ek(a);
		      if (d & 4) {
		        if (null === a.stateNode) throw Error(p(162));
		        e = a.stateNode;
		        f = a.memoizedProps;
		        try {
		          e.nodeValue = f;
		        } catch (t) {
		          W(a, a.return, t);
		        }
		      }
		      break;
		    case 3:
		      ck(b, a);
		      ek(a);
		      if (d & 4 && null !== c && c.memoizedState.isDehydrated) try {
		        bd(b.containerInfo);
		      } catch (t) {
		        W(a, a.return, t);
		      }
		      break;
		    case 4:
		      ck(b, a);
		      ek(a);
		      break;
		    case 13:
		      ck(b, a);
		      ek(a);
		      e = a.child;
		      e.flags & 8192 && (f = null !== e.memoizedState, e.stateNode.isHidden = f, !f || null !== e.alternate && null !== e.alternate.memoizedState || (fk = B()));
		      d & 4 && ak(a);
		      break;
		    case 22:
		      m = null !== c && null !== c.memoizedState;
		      a.mode & 1 ? (U = (l = U) || m, ck(b, a), U = l) : ck(b, a);
		      ek(a);
		      if (d & 8192) {
		        l = null !== a.memoizedState;
		        if ((a.stateNode.isHidden = l) && !m && 0 !== (a.mode & 1)) for (V = a, m = a.child; null !== m;) {
		          for (q = V = m; null !== V;) {
		            r = V;
		            y = r.child;
		            switch (r.tag) {
		              case 0:
		              case 11:
		              case 14:
		              case 15:
		                Pj(4, r, r.return);
		                break;
		              case 1:
		                Lj(r, r.return);
		                var n = r.stateNode;
		                if ("function" === typeof n.componentWillUnmount) {
		                  d = r;
		                  c = r.return;
		                  try {
		                    b = d, n.props = b.memoizedProps, n.state = b.memoizedState, n.componentWillUnmount();
		                  } catch (t) {
		                    W(d, c, t);
		                  }
		                }
		                break;
		              case 5:
		                Lj(r, r.return);
		                break;
		              case 22:
		                if (null !== r.memoizedState) {
		                  gk(q);
		                  continue;
		                }
		            }
		            null !== y ? (y.return = r, V = y) : gk(q);
		          }
		          m = m.sibling;
		        }
		        a: for (m = null, q = a;;) {
		          if (5 === q.tag) {
		            if (null === m) {
		              m = q;
		              try {
		                e = q.stateNode, l ? (f = e.style, "function" === typeof f.setProperty ? f.setProperty("display", "none", "important") : f.display = "none") : (h = q.stateNode, k = q.memoizedProps.style, g = void 0 !== k && null !== k && k.hasOwnProperty("display") ? k.display : null, h.style.display = rb("display", g));
		              } catch (t) {
		                W(a, a.return, t);
		              }
		            }
		          } else if (6 === q.tag) {
		            if (null === m) try {
		              q.stateNode.nodeValue = l ? "" : q.memoizedProps;
		            } catch (t) {
		              W(a, a.return, t);
		            }
		          } else if ((22 !== q.tag && 23 !== q.tag || null === q.memoizedState || q === a) && null !== q.child) {
		            q.child.return = q;
		            q = q.child;
		            continue;
		          }
		          if (q === a) break a;
		          for (; null === q.sibling;) {
		            if (null === q.return || q.return === a) break a;
		            m === q && (m = null);
		            q = q.return;
		          }
		          m === q && (m = null);
		          q.sibling.return = q.return;
		          q = q.sibling;
		        }
		      }
		      break;
		    case 19:
		      ck(b, a);
		      ek(a);
		      d & 4 && ak(a);
		      break;
		    case 21:
		      break;
		    default:
		      ck(b, a), ek(a);
		  }
		}
		function ek(a) {
		  var b = a.flags;
		  if (b & 2) {
		    try {
		      a: {
		        for (var c = a.return; null !== c;) {
		          if (Tj(c)) {
		            var d = c;
		            break a;
		          }
		          c = c.return;
		        }
		        throw Error(p(160));
		      }
		      switch (d.tag) {
		        case 5:
		          var e = d.stateNode;
		          d.flags & 32 && (ob(e, ""), d.flags &= -33);
		          var f = Uj(a);
		          Wj(a, f, e);
		          break;
		        case 3:
		        case 4:
		          var g = d.stateNode.containerInfo,
		            h = Uj(a);
		          Vj(a, h, g);
		          break;
		        default:
		          throw Error(p(161));
		      }
		    } catch (k) {
		      W(a, a.return, k);
		    }
		    a.flags &= -3;
		  }
		  b & 4096 && (a.flags &= -4097);
		}
		function hk(a, b, c) {
		  V = a;
		  ik(a);
		}
		function ik(a, b, c) {
		  for (var d = 0 !== (a.mode & 1); null !== V;) {
		    var e = V,
		      f = e.child;
		    if (22 === e.tag && d) {
		      var g = null !== e.memoizedState || Jj;
		      if (!g) {
		        var h = e.alternate,
		          k = null !== h && null !== h.memoizedState || U;
		        h = Jj;
		        var l = U;
		        Jj = g;
		        if ((U = k) && !l) for (V = e; null !== V;) g = V, k = g.child, 22 === g.tag && null !== g.memoizedState ? jk(e) : null !== k ? (k.return = g, V = k) : jk(e);
		        for (; null !== f;) V = f, ik(f), f = f.sibling;
		        V = e;
		        Jj = h;
		        U = l;
		      }
		      kk(a);
		    } else 0 !== (e.subtreeFlags & 8772) && null !== f ? (f.return = e, V = f) : kk(a);
		  }
		}
		function kk(a) {
		  for (; null !== V;) {
		    var b = V;
		    if (0 !== (b.flags & 8772)) {
		      var c = b.alternate;
		      try {
		        if (0 !== (b.flags & 8772)) switch (b.tag) {
		          case 0:
		          case 11:
		          case 15:
		            U || Qj(5, b);
		            break;
		          case 1:
		            var d = b.stateNode;
		            if (b.flags & 4 && !U) if (null === c) d.componentDidMount();else {
		              var e = b.elementType === b.type ? c.memoizedProps : Ci(b.type, c.memoizedProps);
		              d.componentDidUpdate(e, c.memoizedState, d.__reactInternalSnapshotBeforeUpdate);
		            }
		            var f = b.updateQueue;
		            null !== f && sh(b, f, d);
		            break;
		          case 3:
		            var g = b.updateQueue;
		            if (null !== g) {
		              c = null;
		              if (null !== b.child) switch (b.child.tag) {
		                case 5:
		                  c = b.child.stateNode;
		                  break;
		                case 1:
		                  c = b.child.stateNode;
		              }
		              sh(b, g, c);
		            }
		            break;
		          case 5:
		            var h = b.stateNode;
		            if (null === c && b.flags & 4) {
		              c = h;
		              var k = b.memoizedProps;
		              switch (b.type) {
		                case "button":
		                case "input":
		                case "select":
		                case "textarea":
		                  k.autoFocus && c.focus();
		                  break;
		                case "img":
		                  k.src && (c.src = k.src);
		              }
		            }
		            break;
		          case 6:
		            break;
		          case 4:
		            break;
		          case 12:
		            break;
		          case 13:
		            if (null === b.memoizedState) {
		              var l = b.alternate;
		              if (null !== l) {
		                var m = l.memoizedState;
		                if (null !== m) {
		                  var q = m.dehydrated;
		                  null !== q && bd(q);
		                }
		              }
		            }
		            break;
		          case 19:
		          case 17:
		          case 21:
		          case 22:
		          case 23:
		          case 25:
		            break;
		          default:
		            throw Error(p(163));
		        }
		        U || b.flags & 512 && Rj(b);
		      } catch (r) {
		        W(b, b.return, r);
		      }
		    }
		    if (b === a) {
		      V = null;
		      break;
		    }
		    c = b.sibling;
		    if (null !== c) {
		      c.return = b.return;
		      V = c;
		      break;
		    }
		    V = b.return;
		  }
		}
		function gk(a) {
		  for (; null !== V;) {
		    var b = V;
		    if (b === a) {
		      V = null;
		      break;
		    }
		    var c = b.sibling;
		    if (null !== c) {
		      c.return = b.return;
		      V = c;
		      break;
		    }
		    V = b.return;
		  }
		}
		function jk(a) {
		  for (; null !== V;) {
		    var b = V;
		    try {
		      switch (b.tag) {
		        case 0:
		        case 11:
		        case 15:
		          var c = b.return;
		          try {
		            Qj(4, b);
		          } catch (k) {
		            W(b, c, k);
		          }
		          break;
		        case 1:
		          var d = b.stateNode;
		          if ("function" === typeof d.componentDidMount) {
		            var e = b.return;
		            try {
		              d.componentDidMount();
		            } catch (k) {
		              W(b, e, k);
		            }
		          }
		          var f = b.return;
		          try {
		            Rj(b);
		          } catch (k) {
		            W(b, f, k);
		          }
		          break;
		        case 5:
		          var g = b.return;
		          try {
		            Rj(b);
		          } catch (k) {
		            W(b, g, k);
		          }
		      }
		    } catch (k) {
		      W(b, b.return, k);
		    }
		    if (b === a) {
		      V = null;
		      break;
		    }
		    var h = b.sibling;
		    if (null !== h) {
		      h.return = b.return;
		      V = h;
		      break;
		    }
		    V = b.return;
		  }
		}
		var lk = Math.ceil,
		  mk = ua.ReactCurrentDispatcher,
		  nk = ua.ReactCurrentOwner,
		  ok = ua.ReactCurrentBatchConfig,
		  K = 0,
		  Q = null,
		  Y = null,
		  Z = 0,
		  fj = 0,
		  ej = Uf(0),
		  T = 0,
		  pk = null,
		  rh = 0,
		  qk = 0,
		  rk = 0,
		  sk = null,
		  tk = null,
		  fk = 0,
		  Gj = Infinity,
		  uk = null,
		  Oi = !1,
		  Pi = null,
		  Ri = null,
		  vk = !1,
		  wk = null,
		  xk = 0,
		  yk = 0,
		  zk = null,
		  Ak = -1,
		  Bk = 0;
		function R() {
		  return 0 !== (K & 6) ? B() : -1 !== Ak ? Ak : Ak = B();
		}
		function yi(a) {
		  if (0 === (a.mode & 1)) return 1;
		  if (0 !== (K & 2) && 0 !== Z) return Z & -Z;
		  if (null !== Kg.transition) return 0 === Bk && (Bk = yc()), Bk;
		  a = C;
		  if (0 !== a) return a;
		  a = window.event;
		  a = void 0 === a ? 16 : jd(a.type);
		  return a;
		}
		function gi(a, b, c, d) {
		  if (50 < yk) throw yk = 0, zk = null, Error(p(185));
		  Ac(a, c, d);
		  if (0 === (K & 2) || a !== Q) a === Q && (0 === (K & 2) && (qk |= c), 4 === T && Ck(a, Z)), Dk(a, d), 1 === c && 0 === K && 0 === (b.mode & 1) && (Gj = B() + 500, fg && jg());
		}
		function Dk(a, b) {
		  var c = a.callbackNode;
		  wc(a, b);
		  var d = uc(a, a === Q ? Z : 0);
		  if (0 === d) null !== c && bc(c), a.callbackNode = null, a.callbackPriority = 0;else if (b = d & -d, a.callbackPriority !== b) {
		    null != c && bc(c);
		    if (1 === b) 0 === a.tag ? ig(Ek.bind(null, a)) : hg(Ek.bind(null, a)), Jf(function () {
		      0 === (K & 6) && jg();
		    }), c = null;else {
		      switch (Dc(d)) {
		        case 1:
		          c = fc;
		          break;
		        case 4:
		          c = gc;
		          break;
		        case 16:
		          c = hc;
		          break;
		        case 536870912:
		          c = jc;
		          break;
		        default:
		          c = hc;
		      }
		      c = Fk(c, Gk.bind(null, a));
		    }
		    a.callbackPriority = b;
		    a.callbackNode = c;
		  }
		}
		function Gk(a, b) {
		  Ak = -1;
		  Bk = 0;
		  if (0 !== (K & 6)) throw Error(p(327));
		  var c = a.callbackNode;
		  if (Hk() && a.callbackNode !== c) return null;
		  var d = uc(a, a === Q ? Z : 0);
		  if (0 === d) return null;
		  if (0 !== (d & 30) || 0 !== (d & a.expiredLanes) || b) b = Ik(a, d);else {
		    b = d;
		    var e = K;
		    K |= 2;
		    var f = Jk();
		    if (Q !== a || Z !== b) uk = null, Gj = B() + 500, Kk(a, b);
		    do try {
		      Lk();
		      break;
		    } catch (h) {
		      Mk(a, h);
		    } while (1);
		    $g();
		    mk.current = f;
		    K = e;
		    null !== Y ? b = 0 : (Q = null, Z = 0, b = T);
		  }
		  if (0 !== b) {
		    2 === b && (e = xc(a), 0 !== e && (d = e, b = Nk(a, e)));
		    if (1 === b) throw c = pk, Kk(a, 0), Ck(a, d), Dk(a, B()), c;
		    if (6 === b) Ck(a, d);else {
		      e = a.current.alternate;
		      if (0 === (d & 30) && !Ok(e) && (b = Ik(a, d), 2 === b && (f = xc(a), 0 !== f && (d = f, b = Nk(a, f))), 1 === b)) throw c = pk, Kk(a, 0), Ck(a, d), Dk(a, B()), c;
		      a.finishedWork = e;
		      a.finishedLanes = d;
		      switch (b) {
		        case 0:
		        case 1:
		          throw Error(p(345));
		        case 2:
		          Pk(a, tk, uk);
		          break;
		        case 3:
		          Ck(a, d);
		          if ((d & 130023424) === d && (b = fk + 500 - B(), 10 < b)) {
		            if (0 !== uc(a, 0)) break;
		            e = a.suspendedLanes;
		            if ((e & d) !== d) {
		              R();
		              a.pingedLanes |= a.suspendedLanes & e;
		              break;
		            }
		            a.timeoutHandle = Ff(Pk.bind(null, a, tk, uk), b);
		            break;
		          }
		          Pk(a, tk, uk);
		          break;
		        case 4:
		          Ck(a, d);
		          if ((d & 4194240) === d) break;
		          b = a.eventTimes;
		          for (e = -1; 0 < d;) {
		            var g = 31 - oc(d);
		            f = 1 << g;
		            g = b[g];
		            g > e && (e = g);
		            d &= ~f;
		          }
		          d = e;
		          d = B() - d;
		          d = (120 > d ? 120 : 480 > d ? 480 : 1080 > d ? 1080 : 1920 > d ? 1920 : 3E3 > d ? 3E3 : 4320 > d ? 4320 : 1960 * lk(d / 1960)) - d;
		          if (10 < d) {
		            a.timeoutHandle = Ff(Pk.bind(null, a, tk, uk), d);
		            break;
		          }
		          Pk(a, tk, uk);
		          break;
		        case 5:
		          Pk(a, tk, uk);
		          break;
		        default:
		          throw Error(p(329));
		      }
		    }
		  }
		  Dk(a, B());
		  return a.callbackNode === c ? Gk.bind(null, a) : null;
		}
		function Nk(a, b) {
		  var c = sk;
		  a.current.memoizedState.isDehydrated && (Kk(a, b).flags |= 256);
		  a = Ik(a, b);
		  2 !== a && (b = tk, tk = c, null !== b && Fj(b));
		  return a;
		}
		function Fj(a) {
		  null === tk ? tk = a : tk.push.apply(tk, a);
		}
		function Ok(a) {
		  for (var b = a;;) {
		    if (b.flags & 16384) {
		      var c = b.updateQueue;
		      if (null !== c && (c = c.stores, null !== c)) for (var d = 0; d < c.length; d++) {
		        var e = c[d],
		          f = e.getSnapshot;
		        e = e.value;
		        try {
		          if (!He(f(), e)) return !1;
		        } catch (g) {
		          return !1;
		        }
		      }
		    }
		    c = b.child;
		    if (b.subtreeFlags & 16384 && null !== c) c.return = b, b = c;else {
		      if (b === a) break;
		      for (; null === b.sibling;) {
		        if (null === b.return || b.return === a) return !0;
		        b = b.return;
		      }
		      b.sibling.return = b.return;
		      b = b.sibling;
		    }
		  }
		  return !0;
		}
		function Ck(a, b) {
		  b &= ~rk;
		  b &= ~qk;
		  a.suspendedLanes |= b;
		  a.pingedLanes &= ~b;
		  for (a = a.expirationTimes; 0 < b;) {
		    var c = 31 - oc(b),
		      d = 1 << c;
		    a[c] = -1;
		    b &= ~d;
		  }
		}
		function Ek(a) {
		  if (0 !== (K & 6)) throw Error(p(327));
		  Hk();
		  var b = uc(a, 0);
		  if (0 === (b & 1)) return Dk(a, B()), null;
		  var c = Ik(a, b);
		  if (0 !== a.tag && 2 === c) {
		    var d = xc(a);
		    0 !== d && (b = d, c = Nk(a, d));
		  }
		  if (1 === c) throw c = pk, Kk(a, 0), Ck(a, b), Dk(a, B()), c;
		  if (6 === c) throw Error(p(345));
		  a.finishedWork = a.current.alternate;
		  a.finishedLanes = b;
		  Pk(a, tk, uk);
		  Dk(a, B());
		  return null;
		}
		function Qk(a, b) {
		  var c = K;
		  K |= 1;
		  try {
		    return a(b);
		  } finally {
		    K = c, 0 === K && (Gj = B() + 500, fg && jg());
		  }
		}
		function Rk(a) {
		  null !== wk && 0 === wk.tag && 0 === (K & 6) && Hk();
		  var b = K;
		  K |= 1;
		  var c = ok.transition,
		    d = C;
		  try {
		    if (ok.transition = null, C = 1, a) return a();
		  } finally {
		    C = d, ok.transition = c, K = b, 0 === (K & 6) && jg();
		  }
		}
		function Hj() {
		  fj = ej.current;
		  E(ej);
		}
		function Kk(a, b) {
		  a.finishedWork = null;
		  a.finishedLanes = 0;
		  var c = a.timeoutHandle;
		  -1 !== c && (a.timeoutHandle = -1, Gf(c));
		  if (null !== Y) for (c = Y.return; null !== c;) {
		    var d = c;
		    wg(d);
		    switch (d.tag) {
		      case 1:
		        d = d.type.childContextTypes;
		        null !== d && void 0 !== d && $f();
		        break;
		      case 3:
		        zh();
		        E(Wf);
		        E(H);
		        Eh();
		        break;
		      case 5:
		        Bh(d);
		        break;
		      case 4:
		        zh();
		        break;
		      case 13:
		        E(L);
		        break;
		      case 19:
		        E(L);
		        break;
		      case 10:
		        ah(d.type._context);
		        break;
		      case 22:
		      case 23:
		        Hj();
		    }
		    c = c.return;
		  }
		  Q = a;
		  Y = a = Pg(a.current, null);
		  Z = fj = b;
		  T = 0;
		  pk = null;
		  rk = qk = rh = 0;
		  tk = sk = null;
		  if (null !== fh) {
		    for (b = 0; b < fh.length; b++) if (c = fh[b], d = c.interleaved, null !== d) {
		      c.interleaved = null;
		      var e = d.next,
		        f = c.pending;
		      if (null !== f) {
		        var g = f.next;
		        f.next = e;
		        d.next = g;
		      }
		      c.pending = d;
		    }
		    fh = null;
		  }
		  return a;
		}
		function Mk(a, b) {
		  do {
		    var c = Y;
		    try {
		      $g();
		      Fh.current = Rh;
		      if (Ih) {
		        for (var d = M.memoizedState; null !== d;) {
		          var e = d.queue;
		          null !== e && (e.pending = null);
		          d = d.next;
		        }
		        Ih = !1;
		      }
		      Hh = 0;
		      O = N = M = null;
		      Jh = !1;
		      Kh = 0;
		      nk.current = null;
		      if (null === c || null === c.return) {
		        T = 1;
		        pk = b;
		        Y = null;
		        break;
		      }
		      a: {
		        var f = a,
		          g = c.return,
		          h = c,
		          k = b;
		        b = Z;
		        h.flags |= 32768;
		        if (null !== k && "object" === typeof k && "function" === typeof k.then) {
		          var l = k,
		            m = h,
		            q = m.tag;
		          if (0 === (m.mode & 1) && (0 === q || 11 === q || 15 === q)) {
		            var r = m.alternate;
		            r ? (m.updateQueue = r.updateQueue, m.memoizedState = r.memoizedState, m.lanes = r.lanes) : (m.updateQueue = null, m.memoizedState = null);
		          }
		          var y = Ui(g);
		          if (null !== y) {
		            y.flags &= -257;
		            Vi(y, g, h, f, b);
		            y.mode & 1 && Si(f, l, b);
		            b = y;
		            k = l;
		            var n = b.updateQueue;
		            if (null === n) {
		              var t = new Set();
		              t.add(k);
		              b.updateQueue = t;
		            } else n.add(k);
		            break a;
		          } else {
		            if (0 === (b & 1)) {
		              Si(f, l, b);
		              tj();
		              break a;
		            }
		            k = Error(p(426));
		          }
		        } else if (I && h.mode & 1) {
		          var J = Ui(g);
		          if (null !== J) {
		            0 === (J.flags & 65536) && (J.flags |= 256);
		            Vi(J, g, h, f, b);
		            Jg(Ji(k, h));
		            break a;
		          }
		        }
		        f = k = Ji(k, h);
		        4 !== T && (T = 2);
		        null === sk ? sk = [f] : sk.push(f);
		        f = g;
		        do {
		          switch (f.tag) {
		            case 3:
		              f.flags |= 65536;
		              b &= -b;
		              f.lanes |= b;
		              var x = Ni(f, k, b);
		              ph(f, x);
		              break a;
		            case 1:
		              h = k;
		              var w = f.type,
		                u = f.stateNode;
		              if (0 === (f.flags & 128) && ("function" === typeof w.getDerivedStateFromError || null !== u && "function" === typeof u.componentDidCatch && (null === Ri || !Ri.has(u)))) {
		                f.flags |= 65536;
		                b &= -b;
		                f.lanes |= b;
		                var F = Qi(f, h, b);
		                ph(f, F);
		                break a;
		              }
		          }
		          f = f.return;
		        } while (null !== f);
		      }
		      Sk(c);
		    } catch (na) {
		      b = na;
		      Y === c && null !== c && (Y = c = c.return);
		      continue;
		    }
		    break;
		  } while (1);
		}
		function Jk() {
		  var a = mk.current;
		  mk.current = Rh;
		  return null === a ? Rh : a;
		}
		function tj() {
		  if (0 === T || 3 === T || 2 === T) T = 4;
		  null === Q || 0 === (rh & 268435455) && 0 === (qk & 268435455) || Ck(Q, Z);
		}
		function Ik(a, b) {
		  var c = K;
		  K |= 2;
		  var d = Jk();
		  if (Q !== a || Z !== b) uk = null, Kk(a, b);
		  do try {
		    Tk();
		    break;
		  } catch (e) {
		    Mk(a, e);
		  } while (1);
		  $g();
		  K = c;
		  mk.current = d;
		  if (null !== Y) throw Error(p(261));
		  Q = null;
		  Z = 0;
		  return T;
		}
		function Tk() {
		  for (; null !== Y;) Uk(Y);
		}
		function Lk() {
		  for (; null !== Y && !cc();) Uk(Y);
		}
		function Uk(a) {
		  var b = Vk(a.alternate, a, fj);
		  a.memoizedProps = a.pendingProps;
		  null === b ? Sk(a) : Y = b;
		  nk.current = null;
		}
		function Sk(a) {
		  var b = a;
		  do {
		    var c = b.alternate;
		    a = b.return;
		    if (0 === (b.flags & 32768)) {
		      if (c = Ej(c, b, fj), null !== c) {
		        Y = c;
		        return;
		      }
		    } else {
		      c = Ij(c, b);
		      if (null !== c) {
		        c.flags &= 32767;
		        Y = c;
		        return;
		      }
		      if (null !== a) a.flags |= 32768, a.subtreeFlags = 0, a.deletions = null;else {
		        T = 6;
		        Y = null;
		        return;
		      }
		    }
		    b = b.sibling;
		    if (null !== b) {
		      Y = b;
		      return;
		    }
		    Y = b = a;
		  } while (null !== b);
		  0 === T && (T = 5);
		}
		function Pk(a, b, c) {
		  var d = C,
		    e = ok.transition;
		  try {
		    ok.transition = null, C = 1, Wk(a, b, c, d);
		  } finally {
		    ok.transition = e, C = d;
		  }
		  return null;
		}
		function Wk(a, b, c, d) {
		  do Hk(); while (null !== wk);
		  if (0 !== (K & 6)) throw Error(p(327));
		  c = a.finishedWork;
		  var e = a.finishedLanes;
		  if (null === c) return null;
		  a.finishedWork = null;
		  a.finishedLanes = 0;
		  if (c === a.current) throw Error(p(177));
		  a.callbackNode = null;
		  a.callbackPriority = 0;
		  var f = c.lanes | c.childLanes;
		  Bc(a, f);
		  a === Q && (Y = Q = null, Z = 0);
		  0 === (c.subtreeFlags & 2064) && 0 === (c.flags & 2064) || vk || (vk = !0, Fk(hc, function () {
		    Hk();
		    return null;
		  }));
		  f = 0 !== (c.flags & 15990);
		  if (0 !== (c.subtreeFlags & 15990) || f) {
		    f = ok.transition;
		    ok.transition = null;
		    var g = C;
		    C = 1;
		    var h = K;
		    K |= 4;
		    nk.current = null;
		    Oj(a, c);
		    dk(c, a);
		    Oe(Df);
		    dd = !!Cf;
		    Df = Cf = null;
		    a.current = c;
		    hk(c);
		    dc();
		    K = h;
		    C = g;
		    ok.transition = f;
		  } else a.current = c;
		  vk && (vk = !1, wk = a, xk = e);
		  f = a.pendingLanes;
		  0 === f && (Ri = null);
		  mc(c.stateNode);
		  Dk(a, B());
		  if (null !== b) for (d = a.onRecoverableError, c = 0; c < b.length; c++) e = b[c], d(e.value, {
		    componentStack: e.stack,
		    digest: e.digest
		  });
		  if (Oi) throw Oi = !1, a = Pi, Pi = null, a;
		  0 !== (xk & 1) && 0 !== a.tag && Hk();
		  f = a.pendingLanes;
		  0 !== (f & 1) ? a === zk ? yk++ : (yk = 0, zk = a) : yk = 0;
		  jg();
		  return null;
		}
		function Hk() {
		  if (null !== wk) {
		    var a = Dc(xk),
		      b = ok.transition,
		      c = C;
		    try {
		      ok.transition = null;
		      C = 16 > a ? 16 : a;
		      if (null === wk) var d = !1;else {
		        a = wk;
		        wk = null;
		        xk = 0;
		        if (0 !== (K & 6)) throw Error(p(331));
		        var e = K;
		        K |= 4;
		        for (V = a.current; null !== V;) {
		          var f = V,
		            g = f.child;
		          if (0 !== (V.flags & 16)) {
		            var h = f.deletions;
		            if (null !== h) {
		              for (var k = 0; k < h.length; k++) {
		                var l = h[k];
		                for (V = l; null !== V;) {
		                  var m = V;
		                  switch (m.tag) {
		                    case 0:
		                    case 11:
		                    case 15:
		                      Pj(8, m, f);
		                  }
		                  var q = m.child;
		                  if (null !== q) q.return = m, V = q;else for (; null !== V;) {
		                    m = V;
		                    var r = m.sibling,
		                      y = m.return;
		                    Sj(m);
		                    if (m === l) {
		                      V = null;
		                      break;
		                    }
		                    if (null !== r) {
		                      r.return = y;
		                      V = r;
		                      break;
		                    }
		                    V = y;
		                  }
		                }
		              }
		              var n = f.alternate;
		              if (null !== n) {
		                var t = n.child;
		                if (null !== t) {
		                  n.child = null;
		                  do {
		                    var J = t.sibling;
		                    t.sibling = null;
		                    t = J;
		                  } while (null !== t);
		                }
		              }
		              V = f;
		            }
		          }
		          if (0 !== (f.subtreeFlags & 2064) && null !== g) g.return = f, V = g;else b: for (; null !== V;) {
		            f = V;
		            if (0 !== (f.flags & 2048)) switch (f.tag) {
		              case 0:
		              case 11:
		              case 15:
		                Pj(9, f, f.return);
		            }
		            var x = f.sibling;
		            if (null !== x) {
		              x.return = f.return;
		              V = x;
		              break b;
		            }
		            V = f.return;
		          }
		        }
		        var w = a.current;
		        for (V = w; null !== V;) {
		          g = V;
		          var u = g.child;
		          if (0 !== (g.subtreeFlags & 2064) && null !== u) u.return = g, V = u;else b: for (g = w; null !== V;) {
		            h = V;
		            if (0 !== (h.flags & 2048)) try {
		              switch (h.tag) {
		                case 0:
		                case 11:
		                case 15:
		                  Qj(9, h);
		              }
		            } catch (na) {
		              W(h, h.return, na);
		            }
		            if (h === g) {
		              V = null;
		              break b;
		            }
		            var F = h.sibling;
		            if (null !== F) {
		              F.return = h.return;
		              V = F;
		              break b;
		            }
		            V = h.return;
		          }
		        }
		        K = e;
		        jg();
		        if (lc && "function" === typeof lc.onPostCommitFiberRoot) try {
		          lc.onPostCommitFiberRoot(kc, a);
		        } catch (na) {}
		        d = !0;
		      }
		      return d;
		    } finally {
		      C = c, ok.transition = b;
		    }
		  }
		  return !1;
		}
		function Xk(a, b, c) {
		  b = Ji(c, b);
		  b = Ni(a, b, 1);
		  a = nh(a, b, 1);
		  b = R();
		  null !== a && (Ac(a, 1, b), Dk(a, b));
		}
		function W(a, b, c) {
		  if (3 === a.tag) Xk(a, a, c);else for (; null !== b;) {
		    if (3 === b.tag) {
		      Xk(b, a, c);
		      break;
		    } else if (1 === b.tag) {
		      var d = b.stateNode;
		      if ("function" === typeof b.type.getDerivedStateFromError || "function" === typeof d.componentDidCatch && (null === Ri || !Ri.has(d))) {
		        a = Ji(c, a);
		        a = Qi(b, a, 1);
		        b = nh(b, a, 1);
		        a = R();
		        null !== b && (Ac(b, 1, a), Dk(b, a));
		        break;
		      }
		    }
		    b = b.return;
		  }
		}
		function Ti(a, b, c) {
		  var d = a.pingCache;
		  null !== d && d.delete(b);
		  b = R();
		  a.pingedLanes |= a.suspendedLanes & c;
		  Q === a && (Z & c) === c && (4 === T || 3 === T && (Z & 130023424) === Z && 500 > B() - fk ? Kk(a, 0) : rk |= c);
		  Dk(a, b);
		}
		function Yk(a, b) {
		  0 === b && (0 === (a.mode & 1) ? b = 1 : (b = sc, sc <<= 1, 0 === (sc & 130023424) && (sc = 4194304)));
		  var c = R();
		  a = ih(a, b);
		  null !== a && (Ac(a, b, c), Dk(a, c));
		}
		function uj(a) {
		  var b = a.memoizedState,
		    c = 0;
		  null !== b && (c = b.retryLane);
		  Yk(a, c);
		}
		function bk(a, b) {
		  var c = 0;
		  switch (a.tag) {
		    case 13:
		      var d = a.stateNode;
		      var e = a.memoizedState;
		      null !== e && (c = e.retryLane);
		      break;
		    case 19:
		      d = a.stateNode;
		      break;
		    default:
		      throw Error(p(314));
		  }
		  null !== d && d.delete(b);
		  Yk(a, c);
		}
		var Vk;
		Vk = function (a, b, c) {
		  if (null !== a) {
		    if (a.memoizedProps !== b.pendingProps || Wf.current) dh = !0;else {
		      if (0 === (a.lanes & c) && 0 === (b.flags & 128)) return dh = !1, yj(a, b, c);
		      dh = 0 !== (a.flags & 131072) ? !0 : !1;
		    }
		  } else dh = !1, I && 0 !== (b.flags & 1048576) && ug(b, ng, b.index);
		  b.lanes = 0;
		  switch (b.tag) {
		    case 2:
		      var d = b.type;
		      ij(a, b);
		      a = b.pendingProps;
		      var e = Yf(b, H.current);
		      ch(b, c);
		      e = Nh(null, b, d, a, e, c);
		      var f = Sh();
		      b.flags |= 1;
		      "object" === typeof e && null !== e && "function" === typeof e.render && void 0 === e.$$typeof ? (b.tag = 1, b.memoizedState = null, b.updateQueue = null, Zf(d) ? (f = !0, cg(b)) : f = !1, b.memoizedState = null !== e.state && void 0 !== e.state ? e.state : null, kh(b), e.updater = Ei, b.stateNode = e, e._reactInternals = b, Ii(b, d, a, c), b = jj(null, b, d, !0, f, c)) : (b.tag = 0, I && f && vg(b), Xi(null, b, e, c), b = b.child);
		      return b;
		    case 16:
		      d = b.elementType;
		      a: {
		        ij(a, b);
		        a = b.pendingProps;
		        e = d._init;
		        d = e(d._payload);
		        b.type = d;
		        e = b.tag = Zk(d);
		        a = Ci(d, a);
		        switch (e) {
		          case 0:
		            b = cj(null, b, d, a, c);
		            break a;
		          case 1:
		            b = hj(null, b, d, a, c);
		            break a;
		          case 11:
		            b = Yi(null, b, d, a, c);
		            break a;
		          case 14:
		            b = $i(null, b, d, Ci(d.type, a), c);
		            break a;
		        }
		        throw Error(p(306, d, ""));
		      }
		      return b;
		    case 0:
		      return d = b.type, e = b.pendingProps, e = b.elementType === d ? e : Ci(d, e), cj(a, b, d, e, c);
		    case 1:
		      return d = b.type, e = b.pendingProps, e = b.elementType === d ? e : Ci(d, e), hj(a, b, d, e, c);
		    case 3:
		      a: {
		        kj(b);
		        if (null === a) throw Error(p(387));
		        d = b.pendingProps;
		        f = b.memoizedState;
		        e = f.element;
		        lh(a, b);
		        qh(b, d, null, c);
		        var g = b.memoizedState;
		        d = g.element;
		        if (f.isDehydrated) {
		          if (f = {
		            element: d,
		            isDehydrated: !1,
		            cache: g.cache,
		            pendingSuspenseBoundaries: g.pendingSuspenseBoundaries,
		            transitions: g.transitions
		          }, b.updateQueue.baseState = f, b.memoizedState = f, b.flags & 256) {
		            e = Ji(Error(p(423)), b);
		            b = lj(a, b, d, c, e);
		            break a;
		          } else if (d !== e) {
		            e = Ji(Error(p(424)), b);
		            b = lj(a, b, d, c, e);
		            break a;
		          } else for (yg = Lf(b.stateNode.containerInfo.firstChild), xg = b, I = !0, zg = null, c = Vg(b, null, d, c), b.child = c; c;) c.flags = c.flags & -3 | 4096, c = c.sibling;
		        } else {
		          Ig();
		          if (d === e) {
		            b = Zi(a, b, c);
		            break a;
		          }
		          Xi(a, b, d, c);
		        }
		        b = b.child;
		      }
		      return b;
		    case 5:
		      return Ah(b), null === a && Eg(b), d = b.type, e = b.pendingProps, f = null !== a ? a.memoizedProps : null, g = e.children, Ef(d, e) ? g = null : null !== f && Ef(d, f) && (b.flags |= 32), gj(a, b), Xi(a, b, g, c), b.child;
		    case 6:
		      return null === a && Eg(b), null;
		    case 13:
		      return oj(a, b, c);
		    case 4:
		      return yh(b, b.stateNode.containerInfo), d = b.pendingProps, null === a ? b.child = Ug(b, null, d, c) : Xi(a, b, d, c), b.child;
		    case 11:
		      return d = b.type, e = b.pendingProps, e = b.elementType === d ? e : Ci(d, e), Yi(a, b, d, e, c);
		    case 7:
		      return Xi(a, b, b.pendingProps, c), b.child;
		    case 8:
		      return Xi(a, b, b.pendingProps.children, c), b.child;
		    case 12:
		      return Xi(a, b, b.pendingProps.children, c), b.child;
		    case 10:
		      a: {
		        d = b.type._context;
		        e = b.pendingProps;
		        f = b.memoizedProps;
		        g = e.value;
		        G(Wg, d._currentValue);
		        d._currentValue = g;
		        if (null !== f) if (He(f.value, g)) {
		          if (f.children === e.children && !Wf.current) {
		            b = Zi(a, b, c);
		            break a;
		          }
		        } else for (f = b.child, null !== f && (f.return = b); null !== f;) {
		          var h = f.dependencies;
		          if (null !== h) {
		            g = f.child;
		            for (var k = h.firstContext; null !== k;) {
		              if (k.context === d) {
		                if (1 === f.tag) {
		                  k = mh(-1, c & -c);
		                  k.tag = 2;
		                  var l = f.updateQueue;
		                  if (null !== l) {
		                    l = l.shared;
		                    var m = l.pending;
		                    null === m ? k.next = k : (k.next = m.next, m.next = k);
		                    l.pending = k;
		                  }
		                }
		                f.lanes |= c;
		                k = f.alternate;
		                null !== k && (k.lanes |= c);
		                bh(f.return, c, b);
		                h.lanes |= c;
		                break;
		              }
		              k = k.next;
		            }
		          } else if (10 === f.tag) g = f.type === b.type ? null : f.child;else if (18 === f.tag) {
		            g = f.return;
		            if (null === g) throw Error(p(341));
		            g.lanes |= c;
		            h = g.alternate;
		            null !== h && (h.lanes |= c);
		            bh(g, c, b);
		            g = f.sibling;
		          } else g = f.child;
		          if (null !== g) g.return = f;else for (g = f; null !== g;) {
		            if (g === b) {
		              g = null;
		              break;
		            }
		            f = g.sibling;
		            if (null !== f) {
		              f.return = g.return;
		              g = f;
		              break;
		            }
		            g = g.return;
		          }
		          f = g;
		        }
		        Xi(a, b, e.children, c);
		        b = b.child;
		      }
		      return b;
		    case 9:
		      return e = b.type, d = b.pendingProps.children, ch(b, c), e = eh(e), d = d(e), b.flags |= 1, Xi(a, b, d, c), b.child;
		    case 14:
		      return d = b.type, e = Ci(d, b.pendingProps), e = Ci(d.type, e), $i(a, b, d, e, c);
		    case 15:
		      return bj(a, b, b.type, b.pendingProps, c);
		    case 17:
		      return d = b.type, e = b.pendingProps, e = b.elementType === d ? e : Ci(d, e), ij(a, b), b.tag = 1, Zf(d) ? (a = !0, cg(b)) : a = !1, ch(b, c), Gi(b, d, e), Ii(b, d, e, c), jj(null, b, d, !0, a, c);
		    case 19:
		      return xj(a, b, c);
		    case 22:
		      return dj(a, b, c);
		  }
		  throw Error(p(156, b.tag));
		};
		function Fk(a, b) {
		  return ac(a, b);
		}
		function $k(a, b, c, d) {
		  this.tag = a;
		  this.key = c;
		  this.sibling = this.child = this.return = this.stateNode = this.type = this.elementType = null;
		  this.index = 0;
		  this.ref = null;
		  this.pendingProps = b;
		  this.dependencies = this.memoizedState = this.updateQueue = this.memoizedProps = null;
		  this.mode = d;
		  this.subtreeFlags = this.flags = 0;
		  this.deletions = null;
		  this.childLanes = this.lanes = 0;
		  this.alternate = null;
		}
		function Bg(a, b, c, d) {
		  return new $k(a, b, c, d);
		}
		function aj(a) {
		  a = a.prototype;
		  return !(!a || !a.isReactComponent);
		}
		function Zk(a) {
		  if ("function" === typeof a) return aj(a) ? 1 : 0;
		  if (void 0 !== a && null !== a) {
		    a = a.$$typeof;
		    if (a === Da) return 11;
		    if (a === Ga) return 14;
		  }
		  return 2;
		}
		function Pg(a, b) {
		  var c = a.alternate;
		  null === c ? (c = Bg(a.tag, b, a.key, a.mode), c.elementType = a.elementType, c.type = a.type, c.stateNode = a.stateNode, c.alternate = a, a.alternate = c) : (c.pendingProps = b, c.type = a.type, c.flags = 0, c.subtreeFlags = 0, c.deletions = null);
		  c.flags = a.flags & 14680064;
		  c.childLanes = a.childLanes;
		  c.lanes = a.lanes;
		  c.child = a.child;
		  c.memoizedProps = a.memoizedProps;
		  c.memoizedState = a.memoizedState;
		  c.updateQueue = a.updateQueue;
		  b = a.dependencies;
		  c.dependencies = null === b ? null : {
		    lanes: b.lanes,
		    firstContext: b.firstContext
		  };
		  c.sibling = a.sibling;
		  c.index = a.index;
		  c.ref = a.ref;
		  return c;
		}
		function Rg(a, b, c, d, e, f) {
		  var g = 2;
		  d = a;
		  if ("function" === typeof a) aj(a) && (g = 1);else if ("string" === typeof a) g = 5;else a: switch (a) {
		    case ya:
		      return Tg(c.children, e, f, b);
		    case za:
		      g = 8;
		      e |= 8;
		      break;
		    case Aa:
		      return a = Bg(12, c, b, e | 2), a.elementType = Aa, a.lanes = f, a;
		    case Ea:
		      return a = Bg(13, c, b, e), a.elementType = Ea, a.lanes = f, a;
		    case Fa:
		      return a = Bg(19, c, b, e), a.elementType = Fa, a.lanes = f, a;
		    case Ia:
		      return pj(c, e, f, b);
		    default:
		      if ("object" === typeof a && null !== a) switch (a.$$typeof) {
		        case Ba:
		          g = 10;
		          break a;
		        case Ca:
		          g = 9;
		          break a;
		        case Da:
		          g = 11;
		          break a;
		        case Ga:
		          g = 14;
		          break a;
		        case Ha:
		          g = 16;
		          d = null;
		          break a;
		      }
		      throw Error(p(130, null == a ? a : typeof a, ""));
		  }
		  b = Bg(g, c, b, e);
		  b.elementType = a;
		  b.type = d;
		  b.lanes = f;
		  return b;
		}
		function Tg(a, b, c, d) {
		  a = Bg(7, a, d, b);
		  a.lanes = c;
		  return a;
		}
		function pj(a, b, c, d) {
		  a = Bg(22, a, d, b);
		  a.elementType = Ia;
		  a.lanes = c;
		  a.stateNode = {
		    isHidden: !1
		  };
		  return a;
		}
		function Qg(a, b, c) {
		  a = Bg(6, a, null, b);
		  a.lanes = c;
		  return a;
		}
		function Sg(a, b, c) {
		  b = Bg(4, null !== a.children ? a.children : [], a.key, b);
		  b.lanes = c;
		  b.stateNode = {
		    containerInfo: a.containerInfo,
		    pendingChildren: null,
		    implementation: a.implementation
		  };
		  return b;
		}
		function al(a, b, c, d, e) {
		  this.tag = b;
		  this.containerInfo = a;
		  this.finishedWork = this.pingCache = this.current = this.pendingChildren = null;
		  this.timeoutHandle = -1;
		  this.callbackNode = this.pendingContext = this.context = null;
		  this.callbackPriority = 0;
		  this.eventTimes = zc(0);
		  this.expirationTimes = zc(-1);
		  this.entangledLanes = this.finishedLanes = this.mutableReadLanes = this.expiredLanes = this.pingedLanes = this.suspendedLanes = this.pendingLanes = 0;
		  this.entanglements = zc(0);
		  this.identifierPrefix = d;
		  this.onRecoverableError = e;
		  this.mutableSourceEagerHydrationData = null;
		}
		function bl(a, b, c, d, e, f, g, h, k) {
		  a = new al(a, b, c, h, k);
		  1 === b ? (b = 1, !0 === f && (b |= 8)) : b = 0;
		  f = Bg(3, null, null, b);
		  a.current = f;
		  f.stateNode = a;
		  f.memoizedState = {
		    element: d,
		    isDehydrated: c,
		    cache: null,
		    transitions: null,
		    pendingSuspenseBoundaries: null
		  };
		  kh(f);
		  return a;
		}
		function cl(a, b, c) {
		  var d = 3 < arguments.length && void 0 !== arguments[3] ? arguments[3] : null;
		  return {
		    $$typeof: wa,
		    key: null == d ? null : "" + d,
		    children: a,
		    containerInfo: b,
		    implementation: c
		  };
		}
		function dl(a) {
		  if (!a) return Vf;
		  a = a._reactInternals;
		  a: {
		    if (Vb(a) !== a || 1 !== a.tag) throw Error(p(170));
		    var b = a;
		    do {
		      switch (b.tag) {
		        case 3:
		          b = b.stateNode.context;
		          break a;
		        case 1:
		          if (Zf(b.type)) {
		            b = b.stateNode.__reactInternalMemoizedMergedChildContext;
		            break a;
		          }
		      }
		      b = b.return;
		    } while (null !== b);
		    throw Error(p(171));
		  }
		  if (1 === a.tag) {
		    var c = a.type;
		    if (Zf(c)) return bg(a, c, b);
		  }
		  return b;
		}
		function el(a, b, c, d, e, f, g, h, k) {
		  a = bl(c, d, !0, a, e, f, g, h, k);
		  a.context = dl(null);
		  c = a.current;
		  d = R();
		  e = yi(c);
		  f = mh(d, e);
		  f.callback = void 0 !== b && null !== b ? b : null;
		  nh(c, f, e);
		  a.current.lanes = e;
		  Ac(a, e, d);
		  Dk(a, d);
		  return a;
		}
		function fl(a, b, c, d) {
		  var e = b.current,
		    f = R(),
		    g = yi(e);
		  c = dl(c);
		  null === b.context ? b.context = c : b.pendingContext = c;
		  b = mh(f, g);
		  b.payload = {
		    element: a
		  };
		  d = void 0 === d ? null : d;
		  null !== d && (b.callback = d);
		  a = nh(e, b, g);
		  null !== a && (gi(a, e, g, f), oh(a, e, g));
		  return g;
		}
		function gl(a) {
		  a = a.current;
		  if (!a.child) return null;
		  switch (a.child.tag) {
		    case 5:
		      return a.child.stateNode;
		    default:
		      return a.child.stateNode;
		  }
		}
		function hl(a, b) {
		  a = a.memoizedState;
		  if (null !== a && null !== a.dehydrated) {
		    var c = a.retryLane;
		    a.retryLane = 0 !== c && c < b ? c : b;
		  }
		}
		function il(a, b) {
		  hl(a, b);
		  (a = a.alternate) && hl(a, b);
		}
		function jl() {
		  return null;
		}
		var kl = "function" === typeof reportError ? reportError : function (a) {
		  console.error(a);
		};
		function ll(a) {
		  this._internalRoot = a;
		}
		ml.prototype.render = ll.prototype.render = function (a) {
		  var b = this._internalRoot;
		  if (null === b) throw Error(p(409));
		  fl(a, b, null, null);
		};
		ml.prototype.unmount = ll.prototype.unmount = function () {
		  var a = this._internalRoot;
		  if (null !== a) {
		    this._internalRoot = null;
		    var b = a.containerInfo;
		    Rk(function () {
		      fl(null, a, null, null);
		    });
		    b[uf] = null;
		  }
		};
		function ml(a) {
		  this._internalRoot = a;
		}
		ml.prototype.unstable_scheduleHydration = function (a) {
		  if (a) {
		    var b = Hc();
		    a = {
		      blockedOn: null,
		      target: a,
		      priority: b
		    };
		    for (var c = 0; c < Qc.length && 0 !== b && b < Qc[c].priority; c++);
		    Qc.splice(c, 0, a);
		    0 === c && Vc(a);
		  }
		};
		function nl(a) {
		  return !(!a || 1 !== a.nodeType && 9 !== a.nodeType && 11 !== a.nodeType);
		}
		function ol(a) {
		  return !(!a || 1 !== a.nodeType && 9 !== a.nodeType && 11 !== a.nodeType && (8 !== a.nodeType || " react-mount-point-unstable " !== a.nodeValue));
		}
		function pl() {}
		function ql(a, b, c, d, e) {
		  if (e) {
		    if ("function" === typeof d) {
		      var f = d;
		      d = function () {
		        var a = gl(g);
		        f.call(a);
		      };
		    }
		    var g = el(b, d, a, 0, null, !1, !1, "", pl);
		    a._reactRootContainer = g;
		    a[uf] = g.current;
		    sf(8 === a.nodeType ? a.parentNode : a);
		    Rk();
		    return g;
		  }
		  for (; e = a.lastChild;) a.removeChild(e);
		  if ("function" === typeof d) {
		    var h = d;
		    d = function () {
		      var a = gl(k);
		      h.call(a);
		    };
		  }
		  var k = bl(a, 0, !1, null, null, !1, !1, "", pl);
		  a._reactRootContainer = k;
		  a[uf] = k.current;
		  sf(8 === a.nodeType ? a.parentNode : a);
		  Rk(function () {
		    fl(b, k, c, d);
		  });
		  return k;
		}
		function rl(a, b, c, d, e) {
		  var f = c._reactRootContainer;
		  if (f) {
		    var g = f;
		    if ("function" === typeof e) {
		      var h = e;
		      e = function () {
		        var a = gl(g);
		        h.call(a);
		      };
		    }
		    fl(b, g, a, e);
		  } else g = ql(c, b, a, e, d);
		  return gl(g);
		}
		Ec = function (a) {
		  switch (a.tag) {
		    case 3:
		      var b = a.stateNode;
		      if (b.current.memoizedState.isDehydrated) {
		        var c = tc(b.pendingLanes);
		        0 !== c && (Cc(b, c | 1), Dk(b, B()), 0 === (K & 6) && (Gj = B() + 500, jg()));
		      }
		      break;
		    case 13:
		      Rk(function () {
		        var b = ih(a, 1);
		        if (null !== b) {
		          var c = R();
		          gi(b, a, 1, c);
		        }
		      }), il(a, 1);
		  }
		};
		Fc = function (a) {
		  if (13 === a.tag) {
		    var b = ih(a, 134217728);
		    if (null !== b) {
		      var c = R();
		      gi(b, a, 134217728, c);
		    }
		    il(a, 134217728);
		  }
		};
		Gc = function (a) {
		  if (13 === a.tag) {
		    var b = yi(a),
		      c = ih(a, b);
		    if (null !== c) {
		      var d = R();
		      gi(c, a, b, d);
		    }
		    il(a, b);
		  }
		};
		Hc = function () {
		  return C;
		};
		Ic = function (a, b) {
		  var c = C;
		  try {
		    return C = a, b();
		  } finally {
		    C = c;
		  }
		};
		yb = function (a, b, c) {
		  switch (b) {
		    case "input":
		      bb(a, c);
		      b = c.name;
		      if ("radio" === c.type && null != b) {
		        for (c = a; c.parentNode;) c = c.parentNode;
		        c = c.querySelectorAll("input[name=" + JSON.stringify("" + b) + '][type="radio"]');
		        for (b = 0; b < c.length; b++) {
		          var d = c[b];
		          if (d !== a && d.form === a.form) {
		            var e = Db(d);
		            if (!e) throw Error(p(90));
		            Wa(d);
		            bb(d, e);
		          }
		        }
		      }
		      break;
		    case "textarea":
		      ib(a, c);
		      break;
		    case "select":
		      b = c.value, null != b && fb(a, !!c.multiple, b, !1);
		  }
		};
		Gb = Qk;
		Hb = Rk;
		var sl = {
		    usingClientEntryPoint: !1,
		    Events: [Cb, ue, Db, Eb, Fb, Qk]
		  },
		  tl = {
		    findFiberByHostInstance: Wc,
		    bundleType: 0,
		    version: "18.3.1",
		    rendererPackageName: "react-dom"
		  };
		var ul = {
		  bundleType: tl.bundleType,
		  version: tl.version,
		  rendererPackageName: tl.rendererPackageName,
		  rendererConfig: tl.rendererConfig,
		  overrideHookState: null,
		  overrideHookStateDeletePath: null,
		  overrideHookStateRenamePath: null,
		  overrideProps: null,
		  overridePropsDeletePath: null,
		  overridePropsRenamePath: null,
		  setErrorHandler: null,
		  setSuspenseHandler: null,
		  scheduleUpdate: null,
		  currentDispatcherRef: ua.ReactCurrentDispatcher,
		  findHostInstanceByFiber: function (a) {
		    a = Zb(a);
		    return null === a ? null : a.stateNode;
		  },
		  findFiberByHostInstance: tl.findFiberByHostInstance || jl,
		  findHostInstancesForRefresh: null,
		  scheduleRefresh: null,
		  scheduleRoot: null,
		  setRefreshHandler: null,
		  getCurrentFiber: null,
		  reconcilerVersion: "18.3.1-next-f1338f8080-20240426"
		};
		if ("undefined" !== typeof __REACT_DEVTOOLS_GLOBAL_HOOK__) {
		  var vl = __REACT_DEVTOOLS_GLOBAL_HOOK__;
		  if (!vl.isDisabled && vl.supportsFiber) try {
		    kc = vl.inject(ul), lc = vl;
		  } catch (a) {}
		}
		reactDom_production_min.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED = sl;
		reactDom_production_min.createPortal = function (a, b) {
		  var c = 2 < arguments.length && void 0 !== arguments[2] ? arguments[2] : null;
		  if (!nl(b)) throw Error(p(200));
		  return cl(a, b, null, c);
		};
		reactDom_production_min.createRoot = function (a, b) {
		  if (!nl(a)) throw Error(p(299));
		  var c = !1,
		    d = "",
		    e = kl;
		  null !== b && void 0 !== b && (!0 === b.unstable_strictMode && (c = !0), void 0 !== b.identifierPrefix && (d = b.identifierPrefix), void 0 !== b.onRecoverableError && (e = b.onRecoverableError));
		  b = bl(a, 1, !1, null, null, c, !1, d, e);
		  a[uf] = b.current;
		  sf(8 === a.nodeType ? a.parentNode : a);
		  return new ll(b);
		};
		reactDom_production_min.findDOMNode = function (a) {
		  if (null == a) return null;
		  if (1 === a.nodeType) return a;
		  var b = a._reactInternals;
		  if (void 0 === b) {
		    if ("function" === typeof a.render) throw Error(p(188));
		    a = Object.keys(a).join(",");
		    throw Error(p(268, a));
		  }
		  a = Zb(b);
		  a = null === a ? null : a.stateNode;
		  return a;
		};
		reactDom_production_min.flushSync = function (a) {
		  return Rk(a);
		};
		reactDom_production_min.hydrate = function (a, b, c) {
		  if (!ol(b)) throw Error(p(200));
		  return rl(null, a, b, !0, c);
		};
		reactDom_production_min.hydrateRoot = function (a, b, c) {
		  if (!nl(a)) throw Error(p(405));
		  var d = null != c && c.hydratedSources || null,
		    e = !1,
		    f = "",
		    g = kl;
		  null !== c && void 0 !== c && (!0 === c.unstable_strictMode && (e = !0), void 0 !== c.identifierPrefix && (f = c.identifierPrefix), void 0 !== c.onRecoverableError && (g = c.onRecoverableError));
		  b = el(b, null, a, 1, null != c ? c : null, e, !1, f, g);
		  a[uf] = b.current;
		  sf(a);
		  if (d) for (a = 0; a < d.length; a++) c = d[a], e = c._getVersion, e = e(c._source), null == b.mutableSourceEagerHydrationData ? b.mutableSourceEagerHydrationData = [c, e] : b.mutableSourceEagerHydrationData.push(c, e);
		  return new ml(b);
		};
		reactDom_production_min.render = function (a, b, c) {
		  if (!ol(b)) throw Error(p(200));
		  return rl(null, a, b, !1, c);
		};
		reactDom_production_min.unmountComponentAtNode = function (a) {
		  if (!ol(a)) throw Error(p(40));
		  return a._reactRootContainer ? (Rk(function () {
		    rl(null, null, a, !1, function () {
		      a._reactRootContainer = null;
		      a[uf] = null;
		    });
		  }), !0) : !1;
		};
		reactDom_production_min.unstable_batchedUpdates = Qk;
		reactDom_production_min.unstable_renderSubtreeIntoContainer = function (a, b, c, d) {
		  if (!ol(c)) throw Error(p(200));
		  if (null == a || void 0 === a._reactInternals) throw Error(p(38));
		  return rl(a, b, c, !1, d);
		};
		reactDom_production_min.version = "18.3.1-next-f1338f8080-20240426";
		return reactDom_production_min;
	}

	var hasRequiredReactDom;

	function requireReactDom () {
		if (hasRequiredReactDom) return reactDom.exports;
		hasRequiredReactDom = 1;

		function checkDCE() {
		  /* global __REACT_DEVTOOLS_GLOBAL_HOOK__ */
		  if (typeof __REACT_DEVTOOLS_GLOBAL_HOOK__ === 'undefined' || typeof __REACT_DEVTOOLS_GLOBAL_HOOK__.checkDCE !== 'function') {
		    return;
		  }
		  try {
		    // Verify that the code above has been dead code eliminated (DCE'd).
		    __REACT_DEVTOOLS_GLOBAL_HOOK__.checkDCE(checkDCE);
		  } catch (err) {
		    // DevTools shouldn't crash React, no matter what.
		    // We should still report in case we break this code.
		    console.error(err);
		  }
		}
		{
		  // DCE check should happen before ReactDOM bundle executes so that
		  // DevTools can report bad minification during injection.
		  checkDCE();
		  reactDom.exports = requireReactDom_production_min();
		}
		return reactDom.exports;
	}

	var hasRequiredClient;

	function requireClient () {
		if (hasRequiredClient) return client;
		hasRequiredClient = 1;

		var m = requireReactDom();
		{
		  client.createRoot = m.createRoot;
		  client.hydrateRoot = m.hydrateRoot;
		}
		return client;
	}

	var clientExports = requireClient();

	const isString = obj => typeof obj === 'string';
	const defer = () => {
	  let res;
	  let rej;
	  const promise = new Promise((resolve, reject) => {
	    res = resolve;
	    rej = reject;
	  });
	  promise.resolve = res;
	  promise.reject = rej;
	  return promise;
	};
	const makeString = object => {
	  if (object == null) return '';
	  return '' + object;
	};
	const copy = (a, s, t) => {
	  a.forEach(m => {
	    if (s[m]) t[m] = s[m];
	  });
	};
	const lastOfPathSeparatorRegExp = /###/g;
	const cleanKey = key => key && key.indexOf('###') > -1 ? key.replace(lastOfPathSeparatorRegExp, '.') : key;
	const canNotTraverseDeeper = object => !object || isString(object);
	const getLastOfPath = (object, path, Empty) => {
	  const stack = !isString(path) ? path : path.split('.');
	  let stackIndex = 0;
	  while (stackIndex < stack.length - 1) {
	    if (canNotTraverseDeeper(object)) return {};
	    const key = cleanKey(stack[stackIndex]);
	    if (!object[key] && Empty) object[key] = new Empty();
	    if (Object.prototype.hasOwnProperty.call(object, key)) {
	      object = object[key];
	    } else {
	      object = {};
	    }
	    ++stackIndex;
	  }
	  if (canNotTraverseDeeper(object)) return {};
	  return {
	    obj: object,
	    k: cleanKey(stack[stackIndex])
	  };
	};
	const setPath = (object, path, newValue) => {
	  const {
	    obj,
	    k
	  } = getLastOfPath(object, path, Object);
	  if (obj !== undefined || path.length === 1) {
	    obj[k] = newValue;
	    return;
	  }
	  let e = path[path.length - 1];
	  let p = path.slice(0, path.length - 1);
	  let last = getLastOfPath(object, p, Object);
	  while (last.obj === undefined && p.length) {
	    e = `${p[p.length - 1]}.${e}`;
	    p = p.slice(0, p.length - 1);
	    last = getLastOfPath(object, p, Object);
	    if (last && last.obj && typeof last.obj[`${last.k}.${e}`] !== 'undefined') {
	      last.obj = undefined;
	    }
	  }
	  last.obj[`${last.k}.${e}`] = newValue;
	};
	const pushPath = (object, path, newValue, concat) => {
	  const {
	    obj,
	    k
	  } = getLastOfPath(object, path, Object);
	  obj[k] = obj[k] || [];
	  obj[k].push(newValue);
	};
	const getPath = (object, path) => {
	  const {
	    obj,
	    k
	  } = getLastOfPath(object, path);
	  if (!obj) return undefined;
	  return obj[k];
	};
	const getPathWithDefaults = (data, defaultData, key) => {
	  const value = getPath(data, key);
	  if (value !== undefined) {
	    return value;
	  }
	  return getPath(defaultData, key);
	};
	const deepExtend = (target, source, overwrite) => {
	  for (const prop in source) {
	    if (prop !== '__proto__' && prop !== 'constructor') {
	      if (prop in target) {
	        if (isString(target[prop]) || target[prop] instanceof String || isString(source[prop]) || source[prop] instanceof String) {
	          if (overwrite) target[prop] = source[prop];
	        } else {
	          deepExtend(target[prop], source[prop], overwrite);
	        }
	      } else {
	        target[prop] = source[prop];
	      }
	    }
	  }
	  return target;
	};
	const regexEscape = str => str.replace(/[\-\[\]\/\{\}\(\)\*\+\?\.\\\^\$\|]/g, '\\$&');
	var _entityMap = {
	  '&': '&amp;',
	  '<': '&lt;',
	  '>': '&gt;',
	  '"': '&quot;',
	  "'": '&#39;',
	  '/': '&#x2F;'
	};
	const escape = data => {
	  if (isString(data)) {
	    return data.replace(/[&<>"'\/]/g, s => _entityMap[s]);
	  }
	  return data;
	};
	class RegExpCache {
	  constructor(capacity) {
	    this.capacity = capacity;
	    this.regExpMap = new Map();
	    this.regExpQueue = [];
	  }
	  getRegExp(pattern) {
	    const regExpFromCache = this.regExpMap.get(pattern);
	    if (regExpFromCache !== undefined) {
	      return regExpFromCache;
	    }
	    const regExpNew = new RegExp(pattern);
	    if (this.regExpQueue.length === this.capacity) {
	      this.regExpMap.delete(this.regExpQueue.shift());
	    }
	    this.regExpMap.set(pattern, regExpNew);
	    this.regExpQueue.push(pattern);
	    return regExpNew;
	  }
	}
	const chars = [' ', ',', '?', '!', ';'];
	const looksLikeObjectPathRegExpCache = new RegExpCache(20);
	const looksLikeObjectPath = (key, nsSeparator, keySeparator) => {
	  nsSeparator = nsSeparator || '';
	  keySeparator = keySeparator || '';
	  const possibleChars = chars.filter(c => nsSeparator.indexOf(c) < 0 && keySeparator.indexOf(c) < 0);
	  if (possibleChars.length === 0) return true;
	  const r = looksLikeObjectPathRegExpCache.getRegExp(`(${possibleChars.map(c => c === '?' ? '\\?' : c).join('|')})`);
	  let matched = !r.test(key);
	  if (!matched) {
	    const ki = key.indexOf(keySeparator);
	    if (ki > 0 && !r.test(key.substring(0, ki))) {
	      matched = true;
	    }
	  }
	  return matched;
	};
	const deepFind = function (obj, path) {
	  let keySeparator = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : '.';
	  if (!obj) return undefined;
	  if (obj[path]) return obj[path];
	  const tokens = path.split(keySeparator);
	  let current = obj;
	  for (let i = 0; i < tokens.length;) {
	    if (!current || typeof current !== 'object') {
	      return undefined;
	    }
	    let next;
	    let nextPath = '';
	    for (let j = i; j < tokens.length; ++j) {
	      if (j !== i) {
	        nextPath += keySeparator;
	      }
	      nextPath += tokens[j];
	      next = current[nextPath];
	      if (next !== undefined) {
	        if (['string', 'number', 'boolean'].indexOf(typeof next) > -1 && j < tokens.length - 1) {
	          continue;
	        }
	        i += j - i + 1;
	        break;
	      }
	    }
	    current = next;
	  }
	  return current;
	};
	const getCleanedCode = code => code && code.replace('_', '-');
	const consoleLogger = {
	  type: 'logger',
	  log(args) {
	    this.output('log', args);
	  },
	  warn(args) {
	    this.output('warn', args);
	  },
	  error(args) {
	    this.output('error', args);
	  },
	  output(type, args) {
	    if (console && console[type]) console[type].apply(console, args);
	  }
	};
	class Logger {
	  constructor(concreteLogger) {
	    let options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};
	    this.init(concreteLogger, options);
	  }
	  init(concreteLogger) {
	    let options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};
	    this.prefix = options.prefix || 'i18next:';
	    this.logger = concreteLogger || consoleLogger;
	    this.options = options;
	    this.debug = options.debug;
	  }
	  log() {
	    for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
	      args[_key] = arguments[_key];
	    }
	    return this.forward(args, 'log', '', true);
	  }
	  warn() {
	    for (var _len2 = arguments.length, args = new Array(_len2), _key2 = 0; _key2 < _len2; _key2++) {
	      args[_key2] = arguments[_key2];
	    }
	    return this.forward(args, 'warn', '', true);
	  }
	  error() {
	    for (var _len3 = arguments.length, args = new Array(_len3), _key3 = 0; _key3 < _len3; _key3++) {
	      args[_key3] = arguments[_key3];
	    }
	    return this.forward(args, 'error', '');
	  }
	  deprecate() {
	    for (var _len4 = arguments.length, args = new Array(_len4), _key4 = 0; _key4 < _len4; _key4++) {
	      args[_key4] = arguments[_key4];
	    }
	    return this.forward(args, 'warn', 'WARNING DEPRECATED: ', true);
	  }
	  forward(args, lvl, prefix, debugOnly) {
	    if (debugOnly && !this.debug) return null;
	    if (isString(args[0])) args[0] = `${prefix}${this.prefix} ${args[0]}`;
	    return this.logger[lvl](args);
	  }
	  create(moduleName) {
	    return new Logger(this.logger, {
	      ...{
	        prefix: `${this.prefix}:${moduleName}:`
	      },
	      ...this.options
	    });
	  }
	  clone(options) {
	    options = options || this.options;
	    options.prefix = options.prefix || this.prefix;
	    return new Logger(this.logger, options);
	  }
	}
	var baseLogger = new Logger();
	class EventEmitter {
	  constructor() {
	    this.observers = {};
	  }
	  on(events, listener) {
	    events.split(' ').forEach(event => {
	      if (!this.observers[event]) this.observers[event] = new Map();
	      const numListeners = this.observers[event].get(listener) || 0;
	      this.observers[event].set(listener, numListeners + 1);
	    });
	    return this;
	  }
	  off(event, listener) {
	    if (!this.observers[event]) return;
	    if (!listener) {
	      delete this.observers[event];
	      return;
	    }
	    this.observers[event].delete(listener);
	  }
	  emit(event) {
	    for (var _len = arguments.length, args = new Array(_len > 1 ? _len - 1 : 0), _key = 1; _key < _len; _key++) {
	      args[_key - 1] = arguments[_key];
	    }
	    if (this.observers[event]) {
	      const cloned = Array.from(this.observers[event].entries());
	      cloned.forEach(_ref => {
	        let [observer, numTimesAdded] = _ref;
	        for (let i = 0; i < numTimesAdded; i++) {
	          observer(...args);
	        }
	      });
	    }
	    if (this.observers['*']) {
	      const cloned = Array.from(this.observers['*'].entries());
	      cloned.forEach(_ref2 => {
	        let [observer, numTimesAdded] = _ref2;
	        for (let i = 0; i < numTimesAdded; i++) {
	          observer.apply(observer, [event, ...args]);
	        }
	      });
	    }
	  }
	}
	class ResourceStore extends EventEmitter {
	  constructor(data) {
	    let options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {
	      ns: ['translation'],
	      defaultNS: 'translation'
	    };
	    super();
	    this.data = data || {};
	    this.options = options;
	    if (this.options.keySeparator === undefined) {
	      this.options.keySeparator = '.';
	    }
	    if (this.options.ignoreJSONStructure === undefined) {
	      this.options.ignoreJSONStructure = true;
	    }
	  }
	  addNamespaces(ns) {
	    if (this.options.ns.indexOf(ns) < 0) {
	      this.options.ns.push(ns);
	    }
	  }
	  removeNamespaces(ns) {
	    const index = this.options.ns.indexOf(ns);
	    if (index > -1) {
	      this.options.ns.splice(index, 1);
	    }
	  }
	  getResource(lng, ns, key) {
	    let options = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : {};
	    const keySeparator = options.keySeparator !== undefined ? options.keySeparator : this.options.keySeparator;
	    const ignoreJSONStructure = options.ignoreJSONStructure !== undefined ? options.ignoreJSONStructure : this.options.ignoreJSONStructure;
	    let path;
	    if (lng.indexOf('.') > -1) {
	      path = lng.split('.');
	    } else {
	      path = [lng, ns];
	      if (key) {
	        if (Array.isArray(key)) {
	          path.push(...key);
	        } else if (isString(key) && keySeparator) {
	          path.push(...key.split(keySeparator));
	        } else {
	          path.push(key);
	        }
	      }
	    }
	    const result = getPath(this.data, path);
	    if (!result && !ns && !key && lng.indexOf('.') > -1) {
	      lng = path[0];
	      ns = path[1];
	      key = path.slice(2).join('.');
	    }
	    if (result || !ignoreJSONStructure || !isString(key)) return result;
	    return deepFind(this.data && this.data[lng] && this.data[lng][ns], key, keySeparator);
	  }
	  addResource(lng, ns, key, value) {
	    let options = arguments.length > 4 && arguments[4] !== undefined ? arguments[4] : {
	      silent: false
	    };
	    const keySeparator = options.keySeparator !== undefined ? options.keySeparator : this.options.keySeparator;
	    let path = [lng, ns];
	    if (key) path = path.concat(keySeparator ? key.split(keySeparator) : key);
	    if (lng.indexOf('.') > -1) {
	      path = lng.split('.');
	      value = ns;
	      ns = path[1];
	    }
	    this.addNamespaces(ns);
	    setPath(this.data, path, value);
	    if (!options.silent) this.emit('added', lng, ns, key, value);
	  }
	  addResources(lng, ns, resources) {
	    let options = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : {
	      silent: false
	    };
	    for (const m in resources) {
	      if (isString(resources[m]) || Array.isArray(resources[m])) this.addResource(lng, ns, m, resources[m], {
	        silent: true
	      });
	    }
	    if (!options.silent) this.emit('added', lng, ns, resources);
	  }
	  addResourceBundle(lng, ns, resources, deep, overwrite) {
	    let options = arguments.length > 5 && arguments[5] !== undefined ? arguments[5] : {
	      silent: false,
	      skipCopy: false
	    };
	    let path = [lng, ns];
	    if (lng.indexOf('.') > -1) {
	      path = lng.split('.');
	      deep = resources;
	      resources = ns;
	      ns = path[1];
	    }
	    this.addNamespaces(ns);
	    let pack = getPath(this.data, path) || {};
	    if (!options.skipCopy) resources = JSON.parse(JSON.stringify(resources));
	    if (deep) {
	      deepExtend(pack, resources, overwrite);
	    } else {
	      pack = {
	        ...pack,
	        ...resources
	      };
	    }
	    setPath(this.data, path, pack);
	    if (!options.silent) this.emit('added', lng, ns, resources);
	  }
	  removeResourceBundle(lng, ns) {
	    if (this.hasResourceBundle(lng, ns)) {
	      delete this.data[lng][ns];
	    }
	    this.removeNamespaces(ns);
	    this.emit('removed', lng, ns);
	  }
	  hasResourceBundle(lng, ns) {
	    return this.getResource(lng, ns) !== undefined;
	  }
	  getResourceBundle(lng, ns) {
	    if (!ns) ns = this.options.defaultNS;
	    if (this.options.compatibilityAPI === 'v1') return {
	      ...{},
	      ...this.getResource(lng, ns)
	    };
	    return this.getResource(lng, ns);
	  }
	  getDataByLanguage(lng) {
	    return this.data[lng];
	  }
	  hasLanguageSomeTranslations(lng) {
	    const data = this.getDataByLanguage(lng);
	    const n = data && Object.keys(data) || [];
	    return !!n.find(v => data[v] && Object.keys(data[v]).length > 0);
	  }
	  toJSON() {
	    return this.data;
	  }
	}
	var postProcessor = {
	  processors: {},
	  addPostProcessor(module) {
	    this.processors[module.name] = module;
	  },
	  handle(processors, value, key, options, translator) {
	    processors.forEach(processor => {
	      if (this.processors[processor]) value = this.processors[processor].process(value, key, options, translator);
	    });
	    return value;
	  }
	};
	const checkedLoadedFor = {};
	class Translator extends EventEmitter {
	  constructor(services) {
	    let options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};
	    super();
	    copy(['resourceStore', 'languageUtils', 'pluralResolver', 'interpolator', 'backendConnector', 'i18nFormat', 'utils'], services, this);
	    this.options = options;
	    if (this.options.keySeparator === undefined) {
	      this.options.keySeparator = '.';
	    }
	    this.logger = baseLogger.create('translator');
	  }
	  changeLanguage(lng) {
	    if (lng) this.language = lng;
	  }
	  exists(key) {
	    let options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {
	      interpolation: {}
	    };
	    if (key === undefined || key === null) {
	      return false;
	    }
	    const resolved = this.resolve(key, options);
	    return resolved && resolved.res !== undefined;
	  }
	  extractFromKey(key, options) {
	    let nsSeparator = options.nsSeparator !== undefined ? options.nsSeparator : this.options.nsSeparator;
	    if (nsSeparator === undefined) nsSeparator = ':';
	    const keySeparator = options.keySeparator !== undefined ? options.keySeparator : this.options.keySeparator;
	    let namespaces = options.ns || this.options.defaultNS || [];
	    const wouldCheckForNsInKey = nsSeparator && key.indexOf(nsSeparator) > -1;
	    const seemsNaturalLanguage = !this.options.userDefinedKeySeparator && !options.keySeparator && !this.options.userDefinedNsSeparator && !options.nsSeparator && !looksLikeObjectPath(key, nsSeparator, keySeparator);
	    if (wouldCheckForNsInKey && !seemsNaturalLanguage) {
	      const m = key.match(this.interpolator.nestingRegexp);
	      if (m && m.length > 0) {
	        return {
	          key,
	          namespaces: isString(namespaces) ? [namespaces] : namespaces
	        };
	      }
	      const parts = key.split(nsSeparator);
	      if (nsSeparator !== keySeparator || nsSeparator === keySeparator && this.options.ns.indexOf(parts[0]) > -1) namespaces = parts.shift();
	      key = parts.join(keySeparator);
	    }
	    return {
	      key,
	      namespaces: isString(namespaces) ? [namespaces] : namespaces
	    };
	  }
	  translate(keys, options, lastKey) {
	    if (typeof options !== 'object' && this.options.overloadTranslationOptionHandler) {
	      options = this.options.overloadTranslationOptionHandler(arguments);
	    }
	    if (typeof options === 'object') options = {
	      ...options
	    };
	    if (!options) options = {};
	    if (keys === undefined || keys === null) return '';
	    if (!Array.isArray(keys)) keys = [String(keys)];
	    const returnDetails = options.returnDetails !== undefined ? options.returnDetails : this.options.returnDetails;
	    const keySeparator = options.keySeparator !== undefined ? options.keySeparator : this.options.keySeparator;
	    const {
	      key,
	      namespaces
	    } = this.extractFromKey(keys[keys.length - 1], options);
	    const namespace = namespaces[namespaces.length - 1];
	    const lng = options.lng || this.language;
	    const appendNamespaceToCIMode = options.appendNamespaceToCIMode || this.options.appendNamespaceToCIMode;
	    if (lng && lng.toLowerCase() === 'cimode') {
	      if (appendNamespaceToCIMode) {
	        const nsSeparator = options.nsSeparator || this.options.nsSeparator;
	        if (returnDetails) {
	          return {
	            res: `${namespace}${nsSeparator}${key}`,
	            usedKey: key,
	            exactUsedKey: key,
	            usedLng: lng,
	            usedNS: namespace,
	            usedParams: this.getUsedParamsDetails(options)
	          };
	        }
	        return `${namespace}${nsSeparator}${key}`;
	      }
	      if (returnDetails) {
	        return {
	          res: key,
	          usedKey: key,
	          exactUsedKey: key,
	          usedLng: lng,
	          usedNS: namespace,
	          usedParams: this.getUsedParamsDetails(options)
	        };
	      }
	      return key;
	    }
	    const resolved = this.resolve(keys, options);
	    let res = resolved && resolved.res;
	    const resUsedKey = resolved && resolved.usedKey || key;
	    const resExactUsedKey = resolved && resolved.exactUsedKey || key;
	    const resType = Object.prototype.toString.apply(res);
	    const noObject = ['[object Number]', '[object Function]', '[object RegExp]'];
	    const joinArrays = options.joinArrays !== undefined ? options.joinArrays : this.options.joinArrays;
	    const handleAsObjectInI18nFormat = !this.i18nFormat || this.i18nFormat.handleAsObject;
	    const handleAsObject = !isString(res) && typeof res !== 'boolean' && typeof res !== 'number';
	    if (handleAsObjectInI18nFormat && res && handleAsObject && noObject.indexOf(resType) < 0 && !(isString(joinArrays) && Array.isArray(res))) {
	      if (!options.returnObjects && !this.options.returnObjects) {
	        if (!this.options.returnedObjectHandler) {
	          this.logger.warn('accessing an object - but returnObjects options is not enabled!');
	        }
	        const r = this.options.returnedObjectHandler ? this.options.returnedObjectHandler(resUsedKey, res, {
	          ...options,
	          ns: namespaces
	        }) : `key '${key} (${this.language})' returned an object instead of string.`;
	        if (returnDetails) {
	          resolved.res = r;
	          resolved.usedParams = this.getUsedParamsDetails(options);
	          return resolved;
	        }
	        return r;
	      }
	      if (keySeparator) {
	        const resTypeIsArray = Array.isArray(res);
	        const copy = resTypeIsArray ? [] : {};
	        const newKeyToUse = resTypeIsArray ? resExactUsedKey : resUsedKey;
	        for (const m in res) {
	          if (Object.prototype.hasOwnProperty.call(res, m)) {
	            const deepKey = `${newKeyToUse}${keySeparator}${m}`;
	            copy[m] = this.translate(deepKey, {
	              ...options,
	              ...{
	                joinArrays: false,
	                ns: namespaces
	              }
	            });
	            if (copy[m] === deepKey) copy[m] = res[m];
	          }
	        }
	        res = copy;
	      }
	    } else if (handleAsObjectInI18nFormat && isString(joinArrays) && Array.isArray(res)) {
	      res = res.join(joinArrays);
	      if (res) res = this.extendTranslation(res, keys, options, lastKey);
	    } else {
	      let usedDefault = false;
	      let usedKey = false;
	      const needsPluralHandling = options.count !== undefined && !isString(options.count);
	      const hasDefaultValue = Translator.hasDefaultValue(options);
	      const defaultValueSuffix = needsPluralHandling ? this.pluralResolver.getSuffix(lng, options.count, options) : '';
	      const defaultValueSuffixOrdinalFallback = options.ordinal && needsPluralHandling ? this.pluralResolver.getSuffix(lng, options.count, {
	        ordinal: false
	      }) : '';
	      const needsZeroSuffixLookup = needsPluralHandling && !options.ordinal && options.count === 0 && this.pluralResolver.shouldUseIntlApi();
	      const defaultValue = needsZeroSuffixLookup && options[`defaultValue${this.options.pluralSeparator}zero`] || options[`defaultValue${defaultValueSuffix}`] || options[`defaultValue${defaultValueSuffixOrdinalFallback}`] || options.defaultValue;
	      if (!this.isValidLookup(res) && hasDefaultValue) {
	        usedDefault = true;
	        res = defaultValue;
	      }
	      if (!this.isValidLookup(res)) {
	        usedKey = true;
	        res = key;
	      }
	      const missingKeyNoValueFallbackToKey = options.missingKeyNoValueFallbackToKey || this.options.missingKeyNoValueFallbackToKey;
	      const resForMissing = missingKeyNoValueFallbackToKey && usedKey ? undefined : res;
	      const updateMissing = hasDefaultValue && defaultValue !== res && this.options.updateMissing;
	      if (usedKey || usedDefault || updateMissing) {
	        this.logger.log(updateMissing ? 'updateKey' : 'missingKey', lng, namespace, key, updateMissing ? defaultValue : res);
	        if (keySeparator) {
	          const fk = this.resolve(key, {
	            ...options,
	            keySeparator: false
	          });
	          if (fk && fk.res) this.logger.warn('Seems the loaded translations were in flat JSON format instead of nested. Either set keySeparator: false on init or make sure your translations are published in nested format.');
	        }
	        let lngs = [];
	        const fallbackLngs = this.languageUtils.getFallbackCodes(this.options.fallbackLng, options.lng || this.language);
	        if (this.options.saveMissingTo === 'fallback' && fallbackLngs && fallbackLngs[0]) {
	          for (let i = 0; i < fallbackLngs.length; i++) {
	            lngs.push(fallbackLngs[i]);
	          }
	        } else if (this.options.saveMissingTo === 'all') {
	          lngs = this.languageUtils.toResolveHierarchy(options.lng || this.language);
	        } else {
	          lngs.push(options.lng || this.language);
	        }
	        const send = (l, k, specificDefaultValue) => {
	          const defaultForMissing = hasDefaultValue && specificDefaultValue !== res ? specificDefaultValue : resForMissing;
	          if (this.options.missingKeyHandler) {
	            this.options.missingKeyHandler(l, namespace, k, defaultForMissing, updateMissing, options);
	          } else if (this.backendConnector && this.backendConnector.saveMissing) {
	            this.backendConnector.saveMissing(l, namespace, k, defaultForMissing, updateMissing, options);
	          }
	          this.emit('missingKey', l, namespace, k, res);
	        };
	        if (this.options.saveMissing) {
	          if (this.options.saveMissingPlurals && needsPluralHandling) {
	            lngs.forEach(language => {
	              const suffixes = this.pluralResolver.getSuffixes(language, options);
	              if (needsZeroSuffixLookup && options[`defaultValue${this.options.pluralSeparator}zero`] && suffixes.indexOf(`${this.options.pluralSeparator}zero`) < 0) {
	                suffixes.push(`${this.options.pluralSeparator}zero`);
	              }
	              suffixes.forEach(suffix => {
	                send([language], key + suffix, options[`defaultValue${suffix}`] || defaultValue);
	              });
	            });
	          } else {
	            send(lngs, key, defaultValue);
	          }
	        }
	      }
	      res = this.extendTranslation(res, keys, options, resolved, lastKey);
	      if (usedKey && res === key && this.options.appendNamespaceToMissingKey) res = `${namespace}:${key}`;
	      if ((usedKey || usedDefault) && this.options.parseMissingKeyHandler) {
	        if (this.options.compatibilityAPI !== 'v1') {
	          res = this.options.parseMissingKeyHandler(this.options.appendNamespaceToMissingKey ? `${namespace}:${key}` : key, usedDefault ? res : undefined);
	        } else {
	          res = this.options.parseMissingKeyHandler(res);
	        }
	      }
	    }
	    if (returnDetails) {
	      resolved.res = res;
	      resolved.usedParams = this.getUsedParamsDetails(options);
	      return resolved;
	    }
	    return res;
	  }
	  extendTranslation(res, key, options, resolved, lastKey) {
	    var _this = this;
	    if (this.i18nFormat && this.i18nFormat.parse) {
	      res = this.i18nFormat.parse(res, {
	        ...this.options.interpolation.defaultVariables,
	        ...options
	      }, options.lng || this.language || resolved.usedLng, resolved.usedNS, resolved.usedKey, {
	        resolved
	      });
	    } else if (!options.skipInterpolation) {
	      if (options.interpolation) this.interpolator.init({
	        ...options,
	        ...{
	          interpolation: {
	            ...this.options.interpolation,
	            ...options.interpolation
	          }
	        }
	      });
	      const skipOnVariables = isString(res) && (options && options.interpolation && options.interpolation.skipOnVariables !== undefined ? options.interpolation.skipOnVariables : this.options.interpolation.skipOnVariables);
	      let nestBef;
	      if (skipOnVariables) {
	        const nb = res.match(this.interpolator.nestingRegexp);
	        nestBef = nb && nb.length;
	      }
	      let data = options.replace && !isString(options.replace) ? options.replace : options;
	      if (this.options.interpolation.defaultVariables) data = {
	        ...this.options.interpolation.defaultVariables,
	        ...data
	      };
	      res = this.interpolator.interpolate(res, data, options.lng || this.language || resolved.usedLng, options);
	      if (skipOnVariables) {
	        const na = res.match(this.interpolator.nestingRegexp);
	        const nestAft = na && na.length;
	        if (nestBef < nestAft) options.nest = false;
	      }
	      if (!options.lng && this.options.compatibilityAPI !== 'v1' && resolved && resolved.res) options.lng = this.language || resolved.usedLng;
	      if (options.nest !== false) res = this.interpolator.nest(res, function () {
	        for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
	          args[_key] = arguments[_key];
	        }
	        if (lastKey && lastKey[0] === args[0] && !options.context) {
	          _this.logger.warn(`It seems you are nesting recursively key: ${args[0]} in key: ${key[0]}`);
	          return null;
	        }
	        return _this.translate(...args, key);
	      }, options);
	      if (options.interpolation) this.interpolator.reset();
	    }
	    const postProcess = options.postProcess || this.options.postProcess;
	    const postProcessorNames = isString(postProcess) ? [postProcess] : postProcess;
	    if (res !== undefined && res !== null && postProcessorNames && postProcessorNames.length && options.applyPostProcessor !== false) {
	      res = postProcessor.handle(postProcessorNames, res, key, this.options && this.options.postProcessPassResolved ? {
	        i18nResolved: {
	          ...resolved,
	          usedParams: this.getUsedParamsDetails(options)
	        },
	        ...options
	      } : options, this);
	    }
	    return res;
	  }
	  resolve(keys) {
	    let options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};
	    let found;
	    let usedKey;
	    let exactUsedKey;
	    let usedLng;
	    let usedNS;
	    if (isString(keys)) keys = [keys];
	    keys.forEach(k => {
	      if (this.isValidLookup(found)) return;
	      const extracted = this.extractFromKey(k, options);
	      const key = extracted.key;
	      usedKey = key;
	      let namespaces = extracted.namespaces;
	      if (this.options.fallbackNS) namespaces = namespaces.concat(this.options.fallbackNS);
	      const needsPluralHandling = options.count !== undefined && !isString(options.count);
	      const needsZeroSuffixLookup = needsPluralHandling && !options.ordinal && options.count === 0 && this.pluralResolver.shouldUseIntlApi();
	      const needsContextHandling = options.context !== undefined && (isString(options.context) || typeof options.context === 'number') && options.context !== '';
	      const codes = options.lngs ? options.lngs : this.languageUtils.toResolveHierarchy(options.lng || this.language, options.fallbackLng);
	      namespaces.forEach(ns => {
	        if (this.isValidLookup(found)) return;
	        usedNS = ns;
	        if (!checkedLoadedFor[`${codes[0]}-${ns}`] && this.utils && this.utils.hasLoadedNamespace && !this.utils.hasLoadedNamespace(usedNS)) {
	          checkedLoadedFor[`${codes[0]}-${ns}`] = true;
	          this.logger.warn(`key "${usedKey}" for languages "${codes.join(', ')}" won't get resolved as namespace "${usedNS}" was not yet loaded`, 'This means something IS WRONG in your setup. You access the t function before i18next.init / i18next.loadNamespace / i18next.changeLanguage was done. Wait for the callback or Promise to resolve before accessing it!!!');
	        }
	        codes.forEach(code => {
	          if (this.isValidLookup(found)) return;
	          usedLng = code;
	          const finalKeys = [key];
	          if (this.i18nFormat && this.i18nFormat.addLookupKeys) {
	            this.i18nFormat.addLookupKeys(finalKeys, key, code, ns, options);
	          } else {
	            let pluralSuffix;
	            if (needsPluralHandling) pluralSuffix = this.pluralResolver.getSuffix(code, options.count, options);
	            const zeroSuffix = `${this.options.pluralSeparator}zero`;
	            const ordinalPrefix = `${this.options.pluralSeparator}ordinal${this.options.pluralSeparator}`;
	            if (needsPluralHandling) {
	              finalKeys.push(key + pluralSuffix);
	              if (options.ordinal && pluralSuffix.indexOf(ordinalPrefix) === 0) {
	                finalKeys.push(key + pluralSuffix.replace(ordinalPrefix, this.options.pluralSeparator));
	              }
	              if (needsZeroSuffixLookup) {
	                finalKeys.push(key + zeroSuffix);
	              }
	            }
	            if (needsContextHandling) {
	              const contextKey = `${key}${this.options.contextSeparator}${options.context}`;
	              finalKeys.push(contextKey);
	              if (needsPluralHandling) {
	                finalKeys.push(contextKey + pluralSuffix);
	                if (options.ordinal && pluralSuffix.indexOf(ordinalPrefix) === 0) {
	                  finalKeys.push(contextKey + pluralSuffix.replace(ordinalPrefix, this.options.pluralSeparator));
	                }
	                if (needsZeroSuffixLookup) {
	                  finalKeys.push(contextKey + zeroSuffix);
	                }
	              }
	            }
	          }
	          let possibleKey;
	          while (possibleKey = finalKeys.pop()) {
	            if (!this.isValidLookup(found)) {
	              exactUsedKey = possibleKey;
	              found = this.getResource(code, ns, possibleKey, options);
	            }
	          }
	        });
	      });
	    });
	    return {
	      res: found,
	      usedKey,
	      exactUsedKey,
	      usedLng,
	      usedNS
	    };
	  }
	  isValidLookup(res) {
	    return res !== undefined && !(!this.options.returnNull && res === null) && !(!this.options.returnEmptyString && res === '');
	  }
	  getResource(code, ns, key) {
	    let options = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : {};
	    if (this.i18nFormat && this.i18nFormat.getResource) return this.i18nFormat.getResource(code, ns, key, options);
	    return this.resourceStore.getResource(code, ns, key, options);
	  }
	  getUsedParamsDetails() {
	    let options = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
	    const optionsKeys = ['defaultValue', 'ordinal', 'context', 'replace', 'lng', 'lngs', 'fallbackLng', 'ns', 'keySeparator', 'nsSeparator', 'returnObjects', 'returnDetails', 'joinArrays', 'postProcess', 'interpolation'];
	    const useOptionsReplaceForData = options.replace && !isString(options.replace);
	    let data = useOptionsReplaceForData ? options.replace : options;
	    if (useOptionsReplaceForData && typeof options.count !== 'undefined') {
	      data.count = options.count;
	    }
	    if (this.options.interpolation.defaultVariables) {
	      data = {
	        ...this.options.interpolation.defaultVariables,
	        ...data
	      };
	    }
	    if (!useOptionsReplaceForData) {
	      data = {
	        ...data
	      };
	      for (const key of optionsKeys) {
	        delete data[key];
	      }
	    }
	    return data;
	  }
	  static hasDefaultValue(options) {
	    const prefix = 'defaultValue';
	    for (const option in options) {
	      if (Object.prototype.hasOwnProperty.call(options, option) && prefix === option.substring(0, prefix.length) && undefined !== options[option]) {
	        return true;
	      }
	    }
	    return false;
	  }
	}
	const capitalize = string => string.charAt(0).toUpperCase() + string.slice(1);
	class LanguageUtil {
	  constructor(options) {
	    this.options = options;
	    this.supportedLngs = this.options.supportedLngs || false;
	    this.logger = baseLogger.create('languageUtils');
	  }
	  getScriptPartFromCode(code) {
	    code = getCleanedCode(code);
	    if (!code || code.indexOf('-') < 0) return null;
	    const p = code.split('-');
	    if (p.length === 2) return null;
	    p.pop();
	    if (p[p.length - 1].toLowerCase() === 'x') return null;
	    return this.formatLanguageCode(p.join('-'));
	  }
	  getLanguagePartFromCode(code) {
	    code = getCleanedCode(code);
	    if (!code || code.indexOf('-') < 0) return code;
	    const p = code.split('-');
	    return this.formatLanguageCode(p[0]);
	  }
	  formatLanguageCode(code) {
	    if (isString(code) && code.indexOf('-') > -1) {
	      if (typeof Intl !== 'undefined' && typeof Intl.getCanonicalLocales !== 'undefined') {
	        try {
	          let formattedCode = Intl.getCanonicalLocales(code)[0];
	          if (formattedCode && this.options.lowerCaseLng) {
	            formattedCode = formattedCode.toLowerCase();
	          }
	          if (formattedCode) return formattedCode;
	        } catch (e) {}
	      }
	      const specialCases = ['hans', 'hant', 'latn', 'cyrl', 'cans', 'mong', 'arab'];
	      let p = code.split('-');
	      if (this.options.lowerCaseLng) {
	        p = p.map(part => part.toLowerCase());
	      } else if (p.length === 2) {
	        p[0] = p[0].toLowerCase();
	        p[1] = p[1].toUpperCase();
	        if (specialCases.indexOf(p[1].toLowerCase()) > -1) p[1] = capitalize(p[1].toLowerCase());
	      } else if (p.length === 3) {
	        p[0] = p[0].toLowerCase();
	        if (p[1].length === 2) p[1] = p[1].toUpperCase();
	        if (p[0] !== 'sgn' && p[2].length === 2) p[2] = p[2].toUpperCase();
	        if (specialCases.indexOf(p[1].toLowerCase()) > -1) p[1] = capitalize(p[1].toLowerCase());
	        if (specialCases.indexOf(p[2].toLowerCase()) > -1) p[2] = capitalize(p[2].toLowerCase());
	      }
	      return p.join('-');
	    }
	    return this.options.cleanCode || this.options.lowerCaseLng ? code.toLowerCase() : code;
	  }
	  isSupportedCode(code) {
	    if (this.options.load === 'languageOnly' || this.options.nonExplicitSupportedLngs) {
	      code = this.getLanguagePartFromCode(code);
	    }
	    return !this.supportedLngs || !this.supportedLngs.length || this.supportedLngs.indexOf(code) > -1;
	  }
	  getBestMatchFromCodes(codes) {
	    if (!codes) return null;
	    let found;
	    codes.forEach(code => {
	      if (found) return;
	      const cleanedLng = this.formatLanguageCode(code);
	      if (!this.options.supportedLngs || this.isSupportedCode(cleanedLng)) found = cleanedLng;
	    });
	    if (!found && this.options.supportedLngs) {
	      codes.forEach(code => {
	        if (found) return;
	        const lngOnly = this.getLanguagePartFromCode(code);
	        if (this.isSupportedCode(lngOnly)) return found = lngOnly;
	        found = this.options.supportedLngs.find(supportedLng => {
	          if (supportedLng === lngOnly) return supportedLng;
	          if (supportedLng.indexOf('-') < 0 && lngOnly.indexOf('-') < 0) return;
	          if (supportedLng.indexOf('-') > 0 && lngOnly.indexOf('-') < 0 && supportedLng.substring(0, supportedLng.indexOf('-')) === lngOnly) return supportedLng;
	          if (supportedLng.indexOf(lngOnly) === 0 && lngOnly.length > 1) return supportedLng;
	        });
	      });
	    }
	    if (!found) found = this.getFallbackCodes(this.options.fallbackLng)[0];
	    return found;
	  }
	  getFallbackCodes(fallbacks, code) {
	    if (!fallbacks) return [];
	    if (typeof fallbacks === 'function') fallbacks = fallbacks(code);
	    if (isString(fallbacks)) fallbacks = [fallbacks];
	    if (Array.isArray(fallbacks)) return fallbacks;
	    if (!code) return fallbacks.default || [];
	    let found = fallbacks[code];
	    if (!found) found = fallbacks[this.getScriptPartFromCode(code)];
	    if (!found) found = fallbacks[this.formatLanguageCode(code)];
	    if (!found) found = fallbacks[this.getLanguagePartFromCode(code)];
	    if (!found) found = fallbacks.default;
	    return found || [];
	  }
	  toResolveHierarchy(code, fallbackCode) {
	    const fallbackCodes = this.getFallbackCodes(fallbackCode || this.options.fallbackLng || [], code);
	    const codes = [];
	    const addCode = c => {
	      if (!c) return;
	      if (this.isSupportedCode(c)) {
	        codes.push(c);
	      } else {
	        this.logger.warn(`rejecting language code not found in supportedLngs: ${c}`);
	      }
	    };
	    if (isString(code) && (code.indexOf('-') > -1 || code.indexOf('_') > -1)) {
	      if (this.options.load !== 'languageOnly') addCode(this.formatLanguageCode(code));
	      if (this.options.load !== 'languageOnly' && this.options.load !== 'currentOnly') addCode(this.getScriptPartFromCode(code));
	      if (this.options.load !== 'currentOnly') addCode(this.getLanguagePartFromCode(code));
	    } else if (isString(code)) {
	      addCode(this.formatLanguageCode(code));
	    }
	    fallbackCodes.forEach(fc => {
	      if (codes.indexOf(fc) < 0) addCode(this.formatLanguageCode(fc));
	    });
	    return codes;
	  }
	}
	let sets = [{
	  lngs: ['ach', 'ak', 'am', 'arn', 'br', 'fil', 'gun', 'ln', 'mfe', 'mg', 'mi', 'oc', 'pt', 'pt-BR', 'tg', 'tl', 'ti', 'tr', 'uz', 'wa'],
	  nr: [1, 2],
	  fc: 1
	}, {
	  lngs: ['af', 'an', 'ast', 'az', 'bg', 'bn', 'ca', 'da', 'de', 'dev', 'el', 'en', 'eo', 'es', 'et', 'eu', 'fi', 'fo', 'fur', 'fy', 'gl', 'gu', 'ha', 'hi', 'hu', 'hy', 'ia', 'it', 'kk', 'kn', 'ku', 'lb', 'mai', 'ml', 'mn', 'mr', 'nah', 'nap', 'nb', 'ne', 'nl', 'nn', 'no', 'nso', 'pa', 'pap', 'pms', 'ps', 'pt-PT', 'rm', 'sco', 'se', 'si', 'so', 'son', 'sq', 'sv', 'sw', 'ta', 'te', 'tk', 'ur', 'yo'],
	  nr: [1, 2],
	  fc: 2
	}, {
	  lngs: ['ay', 'bo', 'cgg', 'fa', 'ht', 'id', 'ja', 'jbo', 'ka', 'km', 'ko', 'ky', 'lo', 'ms', 'sah', 'su', 'th', 'tt', 'ug', 'vi', 'wo', 'zh'],
	  nr: [1],
	  fc: 3
	}, {
	  lngs: ['be', 'bs', 'cnr', 'dz', 'hr', 'ru', 'sr', 'uk'],
	  nr: [1, 2, 5],
	  fc: 4
	}, {
	  lngs: ['ar'],
	  nr: [0, 1, 2, 3, 11, 100],
	  fc: 5
	}, {
	  lngs: ['cs', 'sk'],
	  nr: [1, 2, 5],
	  fc: 6
	}, {
	  lngs: ['csb', 'pl'],
	  nr: [1, 2, 5],
	  fc: 7
	}, {
	  lngs: ['cy'],
	  nr: [1, 2, 3, 8],
	  fc: 8
	}, {
	  lngs: ['fr'],
	  nr: [1, 2],
	  fc: 9
	}, {
	  lngs: ['ga'],
	  nr: [1, 2, 3, 7, 11],
	  fc: 10
	}, {
	  lngs: ['gd'],
	  nr: [1, 2, 3, 20],
	  fc: 11
	}, {
	  lngs: ['is'],
	  nr: [1, 2],
	  fc: 12
	}, {
	  lngs: ['jv'],
	  nr: [0, 1],
	  fc: 13
	}, {
	  lngs: ['kw'],
	  nr: [1, 2, 3, 4],
	  fc: 14
	}, {
	  lngs: ['lt'],
	  nr: [1, 2, 10],
	  fc: 15
	}, {
	  lngs: ['lv'],
	  nr: [1, 2, 0],
	  fc: 16
	}, {
	  lngs: ['mk'],
	  nr: [1, 2],
	  fc: 17
	}, {
	  lngs: ['mnk'],
	  nr: [0, 1, 2],
	  fc: 18
	}, {
	  lngs: ['mt'],
	  nr: [1, 2, 11, 20],
	  fc: 19
	}, {
	  lngs: ['or'],
	  nr: [2, 1],
	  fc: 2
	}, {
	  lngs: ['ro'],
	  nr: [1, 2, 20],
	  fc: 20
	}, {
	  lngs: ['sl'],
	  nr: [5, 1, 2, 3],
	  fc: 21
	}, {
	  lngs: ['he', 'iw'],
	  nr: [1, 2, 20, 21],
	  fc: 22
	}];
	let _rulesPluralsTypes = {
	  1: n => Number(n > 1),
	  2: n => Number(n != 1),
	  3: n => 0,
	  4: n => Number(n % 10 == 1 && n % 100 != 11 ? 0 : n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 10 || n % 100 >= 20) ? 1 : 2),
	  5: n => Number(n == 0 ? 0 : n == 1 ? 1 : n == 2 ? 2 : n % 100 >= 3 && n % 100 <= 10 ? 3 : n % 100 >= 11 ? 4 : 5),
	  6: n => Number(n == 1 ? 0 : n >= 2 && n <= 4 ? 1 : 2),
	  7: n => Number(n == 1 ? 0 : n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 10 || n % 100 >= 20) ? 1 : 2),
	  8: n => Number(n == 1 ? 0 : n == 2 ? 1 : n != 8 && n != 11 ? 2 : 3),
	  9: n => Number(n >= 2),
	  10: n => Number(n == 1 ? 0 : n == 2 ? 1 : n < 7 ? 2 : n < 11 ? 3 : 4),
	  11: n => Number(n == 1 || n == 11 ? 0 : n == 2 || n == 12 ? 1 : n > 2 && n < 20 ? 2 : 3),
	  12: n => Number(n % 10 != 1 || n % 100 == 11),
	  13: n => Number(n !== 0),
	  14: n => Number(n == 1 ? 0 : n == 2 ? 1 : n == 3 ? 2 : 3),
	  15: n => Number(n % 10 == 1 && n % 100 != 11 ? 0 : n % 10 >= 2 && (n % 100 < 10 || n % 100 >= 20) ? 1 : 2),
	  16: n => Number(n % 10 == 1 && n % 100 != 11 ? 0 : n !== 0 ? 1 : 2),
	  17: n => Number(n == 1 || n % 10 == 1 && n % 100 != 11 ? 0 : 1),
	  18: n => Number(n == 0 ? 0 : n == 1 ? 1 : 2),
	  19: n => Number(n == 1 ? 0 : n == 0 || n % 100 > 1 && n % 100 < 11 ? 1 : n % 100 > 10 && n % 100 < 20 ? 2 : 3),
	  20: n => Number(n == 1 ? 0 : n == 0 || n % 100 > 0 && n % 100 < 20 ? 1 : 2),
	  21: n => Number(n % 100 == 1 ? 1 : n % 100 == 2 ? 2 : n % 100 == 3 || n % 100 == 4 ? 3 : 0),
	  22: n => Number(n == 1 ? 0 : n == 2 ? 1 : (n < 0 || n > 10) && n % 10 == 0 ? 2 : 3)
	};
	const nonIntlVersions = ['v1', 'v2', 'v3'];
	const intlVersions = ['v4'];
	const suffixesOrder = {
	  zero: 0,
	  one: 1,
	  two: 2,
	  few: 3,
	  many: 4,
	  other: 5
	};
	const createRules = () => {
	  const rules = {};
	  sets.forEach(set => {
	    set.lngs.forEach(l => {
	      rules[l] = {
	        numbers: set.nr,
	        plurals: _rulesPluralsTypes[set.fc]
	      };
	    });
	  });
	  return rules;
	};
	class PluralResolver {
	  constructor(languageUtils) {
	    let options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};
	    this.languageUtils = languageUtils;
	    this.options = options;
	    this.logger = baseLogger.create('pluralResolver');
	    if ((!this.options.compatibilityJSON || intlVersions.includes(this.options.compatibilityJSON)) && (typeof Intl === 'undefined' || !Intl.PluralRules)) {
	      this.options.compatibilityJSON = 'v3';
	      this.logger.error('Your environment seems not to be Intl API compatible, use an Intl.PluralRules polyfill. Will fallback to the compatibilityJSON v3 format handling.');
	    }
	    this.rules = createRules();
	    this.pluralRulesCache = {};
	  }
	  addRule(lng, obj) {
	    this.rules[lng] = obj;
	  }
	  clearCache() {
	    this.pluralRulesCache = {};
	  }
	  getRule(code) {
	    let options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};
	    if (this.shouldUseIntlApi()) {
	      const cleanedCode = getCleanedCode(code === 'dev' ? 'en' : code);
	      const type = options.ordinal ? 'ordinal' : 'cardinal';
	      const cacheKey = JSON.stringify({
	        cleanedCode,
	        type
	      });
	      if (cacheKey in this.pluralRulesCache) {
	        return this.pluralRulesCache[cacheKey];
	      }
	      let rule;
	      try {
	        rule = new Intl.PluralRules(cleanedCode, {
	          type
	        });
	      } catch (err) {
	        if (!code.match(/-|_/)) return;
	        const lngPart = this.languageUtils.getLanguagePartFromCode(code);
	        rule = this.getRule(lngPart, options);
	      }
	      this.pluralRulesCache[cacheKey] = rule;
	      return rule;
	    }
	    return this.rules[code] || this.rules[this.languageUtils.getLanguagePartFromCode(code)];
	  }
	  needsPlural(code) {
	    let options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};
	    const rule = this.getRule(code, options);
	    if (this.shouldUseIntlApi()) {
	      return rule && rule.resolvedOptions().pluralCategories.length > 1;
	    }
	    return rule && rule.numbers.length > 1;
	  }
	  getPluralFormsOfKey(code, key) {
	    let options = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : {};
	    return this.getSuffixes(code, options).map(suffix => `${key}${suffix}`);
	  }
	  getSuffixes(code) {
	    let options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};
	    const rule = this.getRule(code, options);
	    if (!rule) {
	      return [];
	    }
	    if (this.shouldUseIntlApi()) {
	      return rule.resolvedOptions().pluralCategories.sort((pluralCategory1, pluralCategory2) => suffixesOrder[pluralCategory1] - suffixesOrder[pluralCategory2]).map(pluralCategory => `${this.options.prepend}${options.ordinal ? `ordinal${this.options.prepend}` : ''}${pluralCategory}`);
	    }
	    return rule.numbers.map(number => this.getSuffix(code, number, options));
	  }
	  getSuffix(code, count) {
	    let options = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : {};
	    const rule = this.getRule(code, options);
	    if (rule) {
	      if (this.shouldUseIntlApi()) {
	        return `${this.options.prepend}${options.ordinal ? `ordinal${this.options.prepend}` : ''}${rule.select(count)}`;
	      }
	      return this.getSuffixRetroCompatible(rule, count);
	    }
	    this.logger.warn(`no plural rule found for: ${code}`);
	    return '';
	  }
	  getSuffixRetroCompatible(rule, count) {
	    const idx = rule.noAbs ? rule.plurals(count) : rule.plurals(Math.abs(count));
	    let suffix = rule.numbers[idx];
	    if (this.options.simplifyPluralSuffix && rule.numbers.length === 2 && rule.numbers[0] === 1) {
	      if (suffix === 2) {
	        suffix = 'plural';
	      } else if (suffix === 1) {
	        suffix = '';
	      }
	    }
	    const returnSuffix = () => this.options.prepend && suffix.toString() ? this.options.prepend + suffix.toString() : suffix.toString();
	    if (this.options.compatibilityJSON === 'v1') {
	      if (suffix === 1) return '';
	      if (typeof suffix === 'number') return `_plural_${suffix.toString()}`;
	      return returnSuffix();
	    } else if (this.options.compatibilityJSON === 'v2') {
	      return returnSuffix();
	    } else if (this.options.simplifyPluralSuffix && rule.numbers.length === 2 && rule.numbers[0] === 1) {
	      return returnSuffix();
	    }
	    return this.options.prepend && idx.toString() ? this.options.prepend + idx.toString() : idx.toString();
	  }
	  shouldUseIntlApi() {
	    return !nonIntlVersions.includes(this.options.compatibilityJSON);
	  }
	}
	const deepFindWithDefaults = function (data, defaultData, key) {
	  let keySeparator = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : '.';
	  let ignoreJSONStructure = arguments.length > 4 && arguments[4] !== undefined ? arguments[4] : true;
	  let path = getPathWithDefaults(data, defaultData, key);
	  if (!path && ignoreJSONStructure && isString(key)) {
	    path = deepFind(data, key, keySeparator);
	    if (path === undefined) path = deepFind(defaultData, key, keySeparator);
	  }
	  return path;
	};
	const regexSafe = val => val.replace(/\$/g, '$$$$');
	class Interpolator {
	  constructor() {
	    let options = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
	    this.logger = baseLogger.create('interpolator');
	    this.options = options;
	    this.format = options.interpolation && options.interpolation.format || (value => value);
	    this.init(options);
	  }
	  init() {
	    let options = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
	    if (!options.interpolation) options.interpolation = {
	      escapeValue: true
	    };
	    const {
	      escape: escape$1,
	      escapeValue,
	      useRawValueToEscape,
	      prefix,
	      prefixEscaped,
	      suffix,
	      suffixEscaped,
	      formatSeparator,
	      unescapeSuffix,
	      unescapePrefix,
	      nestingPrefix,
	      nestingPrefixEscaped,
	      nestingSuffix,
	      nestingSuffixEscaped,
	      nestingOptionsSeparator,
	      maxReplaces,
	      alwaysFormat
	    } = options.interpolation;
	    this.escape = escape$1 !== undefined ? escape$1 : escape;
	    this.escapeValue = escapeValue !== undefined ? escapeValue : true;
	    this.useRawValueToEscape = useRawValueToEscape !== undefined ? useRawValueToEscape : false;
	    this.prefix = prefix ? regexEscape(prefix) : prefixEscaped || '{{';
	    this.suffix = suffix ? regexEscape(suffix) : suffixEscaped || '}}';
	    this.formatSeparator = formatSeparator || ',';
	    this.unescapePrefix = unescapeSuffix ? '' : unescapePrefix || '-';
	    this.unescapeSuffix = this.unescapePrefix ? '' : unescapeSuffix || '';
	    this.nestingPrefix = nestingPrefix ? regexEscape(nestingPrefix) : nestingPrefixEscaped || regexEscape('$t(');
	    this.nestingSuffix = nestingSuffix ? regexEscape(nestingSuffix) : nestingSuffixEscaped || regexEscape(')');
	    this.nestingOptionsSeparator = nestingOptionsSeparator || ',';
	    this.maxReplaces = maxReplaces || 1000;
	    this.alwaysFormat = alwaysFormat !== undefined ? alwaysFormat : false;
	    this.resetRegExp();
	  }
	  reset() {
	    if (this.options) this.init(this.options);
	  }
	  resetRegExp() {
	    const getOrResetRegExp = (existingRegExp, pattern) => {
	      if (existingRegExp && existingRegExp.source === pattern) {
	        existingRegExp.lastIndex = 0;
	        return existingRegExp;
	      }
	      return new RegExp(pattern, 'g');
	    };
	    this.regexp = getOrResetRegExp(this.regexp, `${this.prefix}(.+?)${this.suffix}`);
	    this.regexpUnescape = getOrResetRegExp(this.regexpUnescape, `${this.prefix}${this.unescapePrefix}(.+?)${this.unescapeSuffix}${this.suffix}`);
	    this.nestingRegexp = getOrResetRegExp(this.nestingRegexp, `${this.nestingPrefix}(.+?)${this.nestingSuffix}`);
	  }
	  interpolate(str, data, lng, options) {
	    let match;
	    let value;
	    let replaces;
	    const defaultData = this.options && this.options.interpolation && this.options.interpolation.defaultVariables || {};
	    const handleFormat = key => {
	      if (key.indexOf(this.formatSeparator) < 0) {
	        const path = deepFindWithDefaults(data, defaultData, key, this.options.keySeparator, this.options.ignoreJSONStructure);
	        return this.alwaysFormat ? this.format(path, undefined, lng, {
	          ...options,
	          ...data,
	          interpolationkey: key
	        }) : path;
	      }
	      const p = key.split(this.formatSeparator);
	      const k = p.shift().trim();
	      const f = p.join(this.formatSeparator).trim();
	      return this.format(deepFindWithDefaults(data, defaultData, k, this.options.keySeparator, this.options.ignoreJSONStructure), f, lng, {
	        ...options,
	        ...data,
	        interpolationkey: k
	      });
	    };
	    this.resetRegExp();
	    const missingInterpolationHandler = options && options.missingInterpolationHandler || this.options.missingInterpolationHandler;
	    const skipOnVariables = options && options.interpolation && options.interpolation.skipOnVariables !== undefined ? options.interpolation.skipOnVariables : this.options.interpolation.skipOnVariables;
	    const todos = [{
	      regex: this.regexpUnescape,
	      safeValue: val => regexSafe(val)
	    }, {
	      regex: this.regexp,
	      safeValue: val => this.escapeValue ? regexSafe(this.escape(val)) : regexSafe(val)
	    }];
	    todos.forEach(todo => {
	      replaces = 0;
	      while (match = todo.regex.exec(str)) {
	        const matchedVar = match[1].trim();
	        value = handleFormat(matchedVar);
	        if (value === undefined) {
	          if (typeof missingInterpolationHandler === 'function') {
	            const temp = missingInterpolationHandler(str, match, options);
	            value = isString(temp) ? temp : '';
	          } else if (options && Object.prototype.hasOwnProperty.call(options, matchedVar)) {
	            value = '';
	          } else if (skipOnVariables) {
	            value = match[0];
	            continue;
	          } else {
	            this.logger.warn(`missed to pass in variable ${matchedVar} for interpolating ${str}`);
	            value = '';
	          }
	        } else if (!isString(value) && !this.useRawValueToEscape) {
	          value = makeString(value);
	        }
	        const safeValue = todo.safeValue(value);
	        str = str.replace(match[0], safeValue);
	        if (skipOnVariables) {
	          todo.regex.lastIndex += value.length;
	          todo.regex.lastIndex -= match[0].length;
	        } else {
	          todo.regex.lastIndex = 0;
	        }
	        replaces++;
	        if (replaces >= this.maxReplaces) {
	          break;
	        }
	      }
	    });
	    return str;
	  }
	  nest(str, fc) {
	    let options = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : {};
	    let match;
	    let value;
	    let clonedOptions;
	    const handleHasOptions = (key, inheritedOptions) => {
	      const sep = this.nestingOptionsSeparator;
	      if (key.indexOf(sep) < 0) return key;
	      const c = key.split(new RegExp(`${sep}[ ]*{`));
	      let optionsString = `{${c[1]}`;
	      key = c[0];
	      optionsString = this.interpolate(optionsString, clonedOptions);
	      const matchedSingleQuotes = optionsString.match(/'/g);
	      const matchedDoubleQuotes = optionsString.match(/"/g);
	      if (matchedSingleQuotes && matchedSingleQuotes.length % 2 === 0 && !matchedDoubleQuotes || matchedDoubleQuotes.length % 2 !== 0) {
	        optionsString = optionsString.replace(/'/g, '"');
	      }
	      try {
	        clonedOptions = JSON.parse(optionsString);
	        if (inheritedOptions) clonedOptions = {
	          ...inheritedOptions,
	          ...clonedOptions
	        };
	      } catch (e) {
	        this.logger.warn(`failed parsing options string in nesting for key ${key}`, e);
	        return `${key}${sep}${optionsString}`;
	      }
	      if (clonedOptions.defaultValue && clonedOptions.defaultValue.indexOf(this.prefix) > -1) delete clonedOptions.defaultValue;
	      return key;
	    };
	    while (match = this.nestingRegexp.exec(str)) {
	      let formatters = [];
	      clonedOptions = {
	        ...options
	      };
	      clonedOptions = clonedOptions.replace && !isString(clonedOptions.replace) ? clonedOptions.replace : clonedOptions;
	      clonedOptions.applyPostProcessor = false;
	      delete clonedOptions.defaultValue;
	      let doReduce = false;
	      if (match[0].indexOf(this.formatSeparator) !== -1 && !/{.*}/.test(match[1])) {
	        const r = match[1].split(this.formatSeparator).map(elem => elem.trim());
	        match[1] = r.shift();
	        formatters = r;
	        doReduce = true;
	      }
	      value = fc(handleHasOptions.call(this, match[1].trim(), clonedOptions), clonedOptions);
	      if (value && match[0] === str && !isString(value)) return value;
	      if (!isString(value)) value = makeString(value);
	      if (!value) {
	        this.logger.warn(`missed to resolve ${match[1]} for nesting ${str}`);
	        value = '';
	      }
	      if (doReduce) {
	        value = formatters.reduce((v, f) => this.format(v, f, options.lng, {
	          ...options,
	          interpolationkey: match[1].trim()
	        }), value.trim());
	      }
	      str = str.replace(match[0], value);
	      this.regexp.lastIndex = 0;
	    }
	    return str;
	  }
	}
	const parseFormatStr = formatStr => {
	  let formatName = formatStr.toLowerCase().trim();
	  const formatOptions = {};
	  if (formatStr.indexOf('(') > -1) {
	    const p = formatStr.split('(');
	    formatName = p[0].toLowerCase().trim();
	    const optStr = p[1].substring(0, p[1].length - 1);
	    if (formatName === 'currency' && optStr.indexOf(':') < 0) {
	      if (!formatOptions.currency) formatOptions.currency = optStr.trim();
	    } else if (formatName === 'relativetime' && optStr.indexOf(':') < 0) {
	      if (!formatOptions.range) formatOptions.range = optStr.trim();
	    } else {
	      const opts = optStr.split(';');
	      opts.forEach(opt => {
	        if (opt) {
	          const [key, ...rest] = opt.split(':');
	          const val = rest.join(':').trim().replace(/^'+|'+$/g, '');
	          const trimmedKey = key.trim();
	          if (!formatOptions[trimmedKey]) formatOptions[trimmedKey] = val;
	          if (val === 'false') formatOptions[trimmedKey] = false;
	          if (val === 'true') formatOptions[trimmedKey] = true;
	          if (!isNaN(val)) formatOptions[trimmedKey] = parseInt(val, 10);
	        }
	      });
	    }
	  }
	  return {
	    formatName,
	    formatOptions
	  };
	};
	const createCachedFormatter = fn => {
	  const cache = {};
	  return (val, lng, options) => {
	    let optForCache = options;
	    if (options && options.interpolationkey && options.formatParams && options.formatParams[options.interpolationkey] && options[options.interpolationkey]) {
	      optForCache = {
	        ...optForCache,
	        [options.interpolationkey]: undefined
	      };
	    }
	    const key = lng + JSON.stringify(optForCache);
	    let formatter = cache[key];
	    if (!formatter) {
	      formatter = fn(getCleanedCode(lng), options);
	      cache[key] = formatter;
	    }
	    return formatter(val);
	  };
	};
	class Formatter {
	  constructor() {
	    let options = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
	    this.logger = baseLogger.create('formatter');
	    this.options = options;
	    this.formats = {
	      number: createCachedFormatter((lng, opt) => {
	        const formatter = new Intl.NumberFormat(lng, {
	          ...opt
	        });
	        return val => formatter.format(val);
	      }),
	      currency: createCachedFormatter((lng, opt) => {
	        const formatter = new Intl.NumberFormat(lng, {
	          ...opt,
	          style: 'currency'
	        });
	        return val => formatter.format(val);
	      }),
	      datetime: createCachedFormatter((lng, opt) => {
	        const formatter = new Intl.DateTimeFormat(lng, {
	          ...opt
	        });
	        return val => formatter.format(val);
	      }),
	      relativetime: createCachedFormatter((lng, opt) => {
	        const formatter = new Intl.RelativeTimeFormat(lng, {
	          ...opt
	        });
	        return val => formatter.format(val, opt.range || 'day');
	      }),
	      list: createCachedFormatter((lng, opt) => {
	        const formatter = new Intl.ListFormat(lng, {
	          ...opt
	        });
	        return val => formatter.format(val);
	      })
	    };
	    this.init(options);
	  }
	  init(services) {
	    let options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {
	      interpolation: {}
	    };
	    this.formatSeparator = options.interpolation.formatSeparator || ',';
	  }
	  add(name, fc) {
	    this.formats[name.toLowerCase().trim()] = fc;
	  }
	  addCached(name, fc) {
	    this.formats[name.toLowerCase().trim()] = createCachedFormatter(fc);
	  }
	  format(value, format, lng) {
	    let options = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : {};
	    const formats = format.split(this.formatSeparator);
	    if (formats.length > 1 && formats[0].indexOf('(') > 1 && formats[0].indexOf(')') < 0 && formats.find(f => f.indexOf(')') > -1)) {
	      const lastIndex = formats.findIndex(f => f.indexOf(')') > -1);
	      formats[0] = [formats[0], ...formats.splice(1, lastIndex)].join(this.formatSeparator);
	    }
	    const result = formats.reduce((mem, f) => {
	      const {
	        formatName,
	        formatOptions
	      } = parseFormatStr(f);
	      if (this.formats[formatName]) {
	        let formatted = mem;
	        try {
	          const valOptions = options && options.formatParams && options.formatParams[options.interpolationkey] || {};
	          const l = valOptions.locale || valOptions.lng || options.locale || options.lng || lng;
	          formatted = this.formats[formatName](mem, l, {
	            ...formatOptions,
	            ...options,
	            ...valOptions
	          });
	        } catch (error) {
	          this.logger.warn(error);
	        }
	        return formatted;
	      } else {
	        this.logger.warn(`there was no format function for ${formatName}`);
	      }
	      return mem;
	    }, value);
	    return result;
	  }
	}
	const removePending = (q, name) => {
	  if (q.pending[name] !== undefined) {
	    delete q.pending[name];
	    q.pendingCount--;
	  }
	};
	class Connector extends EventEmitter {
	  constructor(backend, store, services) {
	    let options = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : {};
	    super();
	    this.backend = backend;
	    this.store = store;
	    this.services = services;
	    this.languageUtils = services.languageUtils;
	    this.options = options;
	    this.logger = baseLogger.create('backendConnector');
	    this.waitingReads = [];
	    this.maxParallelReads = options.maxParallelReads || 10;
	    this.readingCalls = 0;
	    this.maxRetries = options.maxRetries >= 0 ? options.maxRetries : 5;
	    this.retryTimeout = options.retryTimeout >= 1 ? options.retryTimeout : 350;
	    this.state = {};
	    this.queue = [];
	    if (this.backend && this.backend.init) {
	      this.backend.init(services, options.backend, options);
	    }
	  }
	  queueLoad(languages, namespaces, options, callback) {
	    const toLoad = {};
	    const pending = {};
	    const toLoadLanguages = {};
	    const toLoadNamespaces = {};
	    languages.forEach(lng => {
	      let hasAllNamespaces = true;
	      namespaces.forEach(ns => {
	        const name = `${lng}|${ns}`;
	        if (!options.reload && this.store.hasResourceBundle(lng, ns)) {
	          this.state[name] = 2;
	        } else if (this.state[name] < 0) ;else if (this.state[name] === 1) {
	          if (pending[name] === undefined) pending[name] = true;
	        } else {
	          this.state[name] = 1;
	          hasAllNamespaces = false;
	          if (pending[name] === undefined) pending[name] = true;
	          if (toLoad[name] === undefined) toLoad[name] = true;
	          if (toLoadNamespaces[ns] === undefined) toLoadNamespaces[ns] = true;
	        }
	      });
	      if (!hasAllNamespaces) toLoadLanguages[lng] = true;
	    });
	    if (Object.keys(toLoad).length || Object.keys(pending).length) {
	      this.queue.push({
	        pending,
	        pendingCount: Object.keys(pending).length,
	        loaded: {},
	        errors: [],
	        callback
	      });
	    }
	    return {
	      toLoad: Object.keys(toLoad),
	      pending: Object.keys(pending),
	      toLoadLanguages: Object.keys(toLoadLanguages),
	      toLoadNamespaces: Object.keys(toLoadNamespaces)
	    };
	  }
	  loaded(name, err, data) {
	    const s = name.split('|');
	    const lng = s[0];
	    const ns = s[1];
	    if (err) this.emit('failedLoading', lng, ns, err);
	    if (!err && data) {
	      this.store.addResourceBundle(lng, ns, data, undefined, undefined, {
	        skipCopy: true
	      });
	    }
	    this.state[name] = err ? -1 : 2;
	    if (err && data) this.state[name] = 0;
	    const loaded = {};
	    this.queue.forEach(q => {
	      pushPath(q.loaded, [lng], ns);
	      removePending(q, name);
	      if (err) q.errors.push(err);
	      if (q.pendingCount === 0 && !q.done) {
	        Object.keys(q.loaded).forEach(l => {
	          if (!loaded[l]) loaded[l] = {};
	          const loadedKeys = q.loaded[l];
	          if (loadedKeys.length) {
	            loadedKeys.forEach(n => {
	              if (loaded[l][n] === undefined) loaded[l][n] = true;
	            });
	          }
	        });
	        q.done = true;
	        if (q.errors.length) {
	          q.callback(q.errors);
	        } else {
	          q.callback();
	        }
	      }
	    });
	    this.emit('loaded', loaded);
	    this.queue = this.queue.filter(q => !q.done);
	  }
	  read(lng, ns, fcName) {
	    let tried = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : 0;
	    let wait = arguments.length > 4 && arguments[4] !== undefined ? arguments[4] : this.retryTimeout;
	    let callback = arguments.length > 5 ? arguments[5] : undefined;
	    if (!lng.length) return callback(null, {});
	    if (this.readingCalls >= this.maxParallelReads) {
	      this.waitingReads.push({
	        lng,
	        ns,
	        fcName,
	        tried,
	        wait,
	        callback
	      });
	      return;
	    }
	    this.readingCalls++;
	    const resolver = (err, data) => {
	      this.readingCalls--;
	      if (this.waitingReads.length > 0) {
	        const next = this.waitingReads.shift();
	        this.read(next.lng, next.ns, next.fcName, next.tried, next.wait, next.callback);
	      }
	      if (err && data && tried < this.maxRetries) {
	        setTimeout(() => {
	          this.read.call(this, lng, ns, fcName, tried + 1, wait * 2, callback);
	        }, wait);
	        return;
	      }
	      callback(err, data);
	    };
	    const fc = this.backend[fcName].bind(this.backend);
	    if (fc.length === 2) {
	      try {
	        const r = fc(lng, ns);
	        if (r && typeof r.then === 'function') {
	          r.then(data => resolver(null, data)).catch(resolver);
	        } else {
	          resolver(null, r);
	        }
	      } catch (err) {
	        resolver(err);
	      }
	      return;
	    }
	    return fc(lng, ns, resolver);
	  }
	  prepareLoading(languages, namespaces) {
	    let options = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : {};
	    let callback = arguments.length > 3 ? arguments[3] : undefined;
	    if (!this.backend) {
	      this.logger.warn('No backend was added via i18next.use. Will not load resources.');
	      return callback && callback();
	    }
	    if (isString(languages)) languages = this.languageUtils.toResolveHierarchy(languages);
	    if (isString(namespaces)) namespaces = [namespaces];
	    const toLoad = this.queueLoad(languages, namespaces, options, callback);
	    if (!toLoad.toLoad.length) {
	      if (!toLoad.pending.length) callback();
	      return null;
	    }
	    toLoad.toLoad.forEach(name => {
	      this.loadOne(name);
	    });
	  }
	  load(languages, namespaces, callback) {
	    this.prepareLoading(languages, namespaces, {}, callback);
	  }
	  reload(languages, namespaces, callback) {
	    this.prepareLoading(languages, namespaces, {
	      reload: true
	    }, callback);
	  }
	  loadOne(name) {
	    let prefix = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : '';
	    const s = name.split('|');
	    const lng = s[0];
	    const ns = s[1];
	    this.read(lng, ns, 'read', undefined, undefined, (err, data) => {
	      if (err) this.logger.warn(`${prefix}loading namespace ${ns} for language ${lng} failed`, err);
	      if (!err && data) this.logger.log(`${prefix}loaded namespace ${ns} for language ${lng}`, data);
	      this.loaded(name, err, data);
	    });
	  }
	  saveMissing(languages, namespace, key, fallbackValue, isUpdate) {
	    let options = arguments.length > 5 && arguments[5] !== undefined ? arguments[5] : {};
	    let clb = arguments.length > 6 && arguments[6] !== undefined ? arguments[6] : () => {};
	    if (this.services.utils && this.services.utils.hasLoadedNamespace && !this.services.utils.hasLoadedNamespace(namespace)) {
	      this.logger.warn(`did not save key "${key}" as the namespace "${namespace}" was not yet loaded`, 'This means something IS WRONG in your setup. You access the t function before i18next.init / i18next.loadNamespace / i18next.changeLanguage was done. Wait for the callback or Promise to resolve before accessing it!!!');
	      return;
	    }
	    if (key === undefined || key === null || key === '') return;
	    if (this.backend && this.backend.create) {
	      const opts = {
	        ...options,
	        isUpdate
	      };
	      const fc = this.backend.create.bind(this.backend);
	      if (fc.length < 6) {
	        try {
	          let r;
	          if (fc.length === 5) {
	            r = fc(languages, namespace, key, fallbackValue, opts);
	          } else {
	            r = fc(languages, namespace, key, fallbackValue);
	          }
	          if (r && typeof r.then === 'function') {
	            r.then(data => clb(null, data)).catch(clb);
	          } else {
	            clb(null, r);
	          }
	        } catch (err) {
	          clb(err);
	        }
	      } else {
	        fc(languages, namespace, key, fallbackValue, clb, opts);
	      }
	    }
	    if (!languages || !languages[0]) return;
	    this.store.addResource(languages[0], namespace, key, fallbackValue);
	  }
	}
	const get = () => ({
	  debug: false,
	  initImmediate: true,
	  ns: ['translation'],
	  defaultNS: ['translation'],
	  fallbackLng: ['dev'],
	  fallbackNS: false,
	  supportedLngs: false,
	  nonExplicitSupportedLngs: false,
	  load: 'all',
	  preload: false,
	  simplifyPluralSuffix: true,
	  keySeparator: '.',
	  nsSeparator: ':',
	  pluralSeparator: '_',
	  contextSeparator: '_',
	  partialBundledLanguages: false,
	  saveMissing: false,
	  updateMissing: false,
	  saveMissingTo: 'fallback',
	  saveMissingPlurals: true,
	  missingKeyHandler: false,
	  missingInterpolationHandler: false,
	  postProcess: false,
	  postProcessPassResolved: false,
	  returnNull: false,
	  returnEmptyString: true,
	  returnObjects: false,
	  joinArrays: false,
	  returnedObjectHandler: false,
	  parseMissingKeyHandler: false,
	  appendNamespaceToMissingKey: false,
	  appendNamespaceToCIMode: false,
	  overloadTranslationOptionHandler: args => {
	    let ret = {};
	    if (typeof args[1] === 'object') ret = args[1];
	    if (isString(args[1])) ret.defaultValue = args[1];
	    if (isString(args[2])) ret.tDescription = args[2];
	    if (typeof args[2] === 'object' || typeof args[3] === 'object') {
	      const options = args[3] || args[2];
	      Object.keys(options).forEach(key => {
	        ret[key] = options[key];
	      });
	    }
	    return ret;
	  },
	  interpolation: {
	    escapeValue: true,
	    format: value => value,
	    prefix: '{{',
	    suffix: '}}',
	    formatSeparator: ',',
	    unescapePrefix: '-',
	    nestingPrefix: '$t(',
	    nestingSuffix: ')',
	    nestingOptionsSeparator: ',',
	    maxReplaces: 1000,
	    skipOnVariables: true
	  }
	});
	const transformOptions = options => {
	  if (isString(options.ns)) options.ns = [options.ns];
	  if (isString(options.fallbackLng)) options.fallbackLng = [options.fallbackLng];
	  if (isString(options.fallbackNS)) options.fallbackNS = [options.fallbackNS];
	  if (options.supportedLngs && options.supportedLngs.indexOf('cimode') < 0) {
	    options.supportedLngs = options.supportedLngs.concat(['cimode']);
	  }
	  return options;
	};
	const noop$1 = () => {};
	const bindMemberFunctions = inst => {
	  const mems = Object.getOwnPropertyNames(Object.getPrototypeOf(inst));
	  mems.forEach(mem => {
	    if (typeof inst[mem] === 'function') {
	      inst[mem] = inst[mem].bind(inst);
	    }
	  });
	};
	class I18n extends EventEmitter {
	  constructor() {
	    let options = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
	    let callback = arguments.length > 1 ? arguments[1] : undefined;
	    super();
	    this.options = transformOptions(options);
	    this.services = {};
	    this.logger = baseLogger;
	    this.modules = {
	      external: []
	    };
	    bindMemberFunctions(this);
	    if (callback && !this.isInitialized && !options.isClone) {
	      if (!this.options.initImmediate) {
	        this.init(options, callback);
	        return this;
	      }
	      setTimeout(() => {
	        this.init(options, callback);
	      }, 0);
	    }
	  }
	  init() {
	    var _this = this;
	    let options = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
	    let callback = arguments.length > 1 ? arguments[1] : undefined;
	    this.isInitializing = true;
	    if (typeof options === 'function') {
	      callback = options;
	      options = {};
	    }
	    if (!options.defaultNS && options.defaultNS !== false && options.ns) {
	      if (isString(options.ns)) {
	        options.defaultNS = options.ns;
	      } else if (options.ns.indexOf('translation') < 0) {
	        options.defaultNS = options.ns[0];
	      }
	    }
	    const defOpts = get();
	    this.options = {
	      ...defOpts,
	      ...this.options,
	      ...transformOptions(options)
	    };
	    if (this.options.compatibilityAPI !== 'v1') {
	      this.options.interpolation = {
	        ...defOpts.interpolation,
	        ...this.options.interpolation
	      };
	    }
	    if (options.keySeparator !== undefined) {
	      this.options.userDefinedKeySeparator = options.keySeparator;
	    }
	    if (options.nsSeparator !== undefined) {
	      this.options.userDefinedNsSeparator = options.nsSeparator;
	    }
	    const createClassOnDemand = ClassOrObject => {
	      if (!ClassOrObject) return null;
	      if (typeof ClassOrObject === 'function') return new ClassOrObject();
	      return ClassOrObject;
	    };
	    if (!this.options.isClone) {
	      if (this.modules.logger) {
	        baseLogger.init(createClassOnDemand(this.modules.logger), this.options);
	      } else {
	        baseLogger.init(null, this.options);
	      }
	      let formatter;
	      if (this.modules.formatter) {
	        formatter = this.modules.formatter;
	      } else if (typeof Intl !== 'undefined') {
	        formatter = Formatter;
	      }
	      const lu = new LanguageUtil(this.options);
	      this.store = new ResourceStore(this.options.resources, this.options);
	      const s = this.services;
	      s.logger = baseLogger;
	      s.resourceStore = this.store;
	      s.languageUtils = lu;
	      s.pluralResolver = new PluralResolver(lu, {
	        prepend: this.options.pluralSeparator,
	        compatibilityJSON: this.options.compatibilityJSON,
	        simplifyPluralSuffix: this.options.simplifyPluralSuffix
	      });
	      if (formatter && (!this.options.interpolation.format || this.options.interpolation.format === defOpts.interpolation.format)) {
	        s.formatter = createClassOnDemand(formatter);
	        s.formatter.init(s, this.options);
	        this.options.interpolation.format = s.formatter.format.bind(s.formatter);
	      }
	      s.interpolator = new Interpolator(this.options);
	      s.utils = {
	        hasLoadedNamespace: this.hasLoadedNamespace.bind(this)
	      };
	      s.backendConnector = new Connector(createClassOnDemand(this.modules.backend), s.resourceStore, s, this.options);
	      s.backendConnector.on('*', function (event) {
	        for (var _len = arguments.length, args = new Array(_len > 1 ? _len - 1 : 0), _key = 1; _key < _len; _key++) {
	          args[_key - 1] = arguments[_key];
	        }
	        _this.emit(event, ...args);
	      });
	      if (this.modules.languageDetector) {
	        s.languageDetector = createClassOnDemand(this.modules.languageDetector);
	        if (s.languageDetector.init) s.languageDetector.init(s, this.options.detection, this.options);
	      }
	      if (this.modules.i18nFormat) {
	        s.i18nFormat = createClassOnDemand(this.modules.i18nFormat);
	        if (s.i18nFormat.init) s.i18nFormat.init(this);
	      }
	      this.translator = new Translator(this.services, this.options);
	      this.translator.on('*', function (event) {
	        for (var _len2 = arguments.length, args = new Array(_len2 > 1 ? _len2 - 1 : 0), _key2 = 1; _key2 < _len2; _key2++) {
	          args[_key2 - 1] = arguments[_key2];
	        }
	        _this.emit(event, ...args);
	      });
	      this.modules.external.forEach(m => {
	        if (m.init) m.init(this);
	      });
	    }
	    this.format = this.options.interpolation.format;
	    if (!callback) callback = noop$1;
	    if (this.options.fallbackLng && !this.services.languageDetector && !this.options.lng) {
	      const codes = this.services.languageUtils.getFallbackCodes(this.options.fallbackLng);
	      if (codes.length > 0 && codes[0] !== 'dev') this.options.lng = codes[0];
	    }
	    if (!this.services.languageDetector && !this.options.lng) {
	      this.logger.warn('init: no languageDetector is used and no lng is defined');
	    }
	    const storeApi = ['getResource', 'hasResourceBundle', 'getResourceBundle', 'getDataByLanguage'];
	    storeApi.forEach(fcName => {
	      this[fcName] = function () {
	        return _this.store[fcName](...arguments);
	      };
	    });
	    const storeApiChained = ['addResource', 'addResources', 'addResourceBundle', 'removeResourceBundle'];
	    storeApiChained.forEach(fcName => {
	      this[fcName] = function () {
	        _this.store[fcName](...arguments);
	        return _this;
	      };
	    });
	    const deferred = defer();
	    const load = () => {
	      const finish = (err, t) => {
	        this.isInitializing = false;
	        if (this.isInitialized && !this.initializedStoreOnce) this.logger.warn('init: i18next is already initialized. You should call init just once!');
	        this.isInitialized = true;
	        if (!this.options.isClone) this.logger.log('initialized', this.options);
	        this.emit('initialized', this.options);
	        deferred.resolve(t);
	        callback(err, t);
	      };
	      if (this.languages && this.options.compatibilityAPI !== 'v1' && !this.isInitialized) return finish(null, this.t.bind(this));
	      this.changeLanguage(this.options.lng, finish);
	    };
	    if (this.options.resources || !this.options.initImmediate) {
	      load();
	    } else {
	      setTimeout(load, 0);
	    }
	    return deferred;
	  }
	  loadResources(language) {
	    let callback = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : noop$1;
	    let usedCallback = callback;
	    const usedLng = isString(language) ? language : this.language;
	    if (typeof language === 'function') usedCallback = language;
	    if (!this.options.resources || this.options.partialBundledLanguages) {
	      if (usedLng && usedLng.toLowerCase() === 'cimode' && (!this.options.preload || this.options.preload.length === 0)) return usedCallback();
	      const toLoad = [];
	      const append = lng => {
	        if (!lng) return;
	        if (lng === 'cimode') return;
	        const lngs = this.services.languageUtils.toResolveHierarchy(lng);
	        lngs.forEach(l => {
	          if (l === 'cimode') return;
	          if (toLoad.indexOf(l) < 0) toLoad.push(l);
	        });
	      };
	      if (!usedLng) {
	        const fallbacks = this.services.languageUtils.getFallbackCodes(this.options.fallbackLng);
	        fallbacks.forEach(l => append(l));
	      } else {
	        append(usedLng);
	      }
	      if (this.options.preload) {
	        this.options.preload.forEach(l => append(l));
	      }
	      this.services.backendConnector.load(toLoad, this.options.ns, e => {
	        if (!e && !this.resolvedLanguage && this.language) this.setResolvedLanguage(this.language);
	        usedCallback(e);
	      });
	    } else {
	      usedCallback(null);
	    }
	  }
	  reloadResources(lngs, ns, callback) {
	    const deferred = defer();
	    if (typeof lngs === 'function') {
	      callback = lngs;
	      lngs = undefined;
	    }
	    if (typeof ns === 'function') {
	      callback = ns;
	      ns = undefined;
	    }
	    if (!lngs) lngs = this.languages;
	    if (!ns) ns = this.options.ns;
	    if (!callback) callback = noop$1;
	    this.services.backendConnector.reload(lngs, ns, err => {
	      deferred.resolve();
	      callback(err);
	    });
	    return deferred;
	  }
	  use(module) {
	    if (!module) throw new Error('You are passing an undefined module! Please check the object you are passing to i18next.use()');
	    if (!module.type) throw new Error('You are passing a wrong module! Please check the object you are passing to i18next.use()');
	    if (module.type === 'backend') {
	      this.modules.backend = module;
	    }
	    if (module.type === 'logger' || module.log && module.warn && module.error) {
	      this.modules.logger = module;
	    }
	    if (module.type === 'languageDetector') {
	      this.modules.languageDetector = module;
	    }
	    if (module.type === 'i18nFormat') {
	      this.modules.i18nFormat = module;
	    }
	    if (module.type === 'postProcessor') {
	      postProcessor.addPostProcessor(module);
	    }
	    if (module.type === 'formatter') {
	      this.modules.formatter = module;
	    }
	    if (module.type === '3rdParty') {
	      this.modules.external.push(module);
	    }
	    return this;
	  }
	  setResolvedLanguage(l) {
	    if (!l || !this.languages) return;
	    if (['cimode', 'dev'].indexOf(l) > -1) return;
	    for (let li = 0; li < this.languages.length; li++) {
	      const lngInLngs = this.languages[li];
	      if (['cimode', 'dev'].indexOf(lngInLngs) > -1) continue;
	      if (this.store.hasLanguageSomeTranslations(lngInLngs)) {
	        this.resolvedLanguage = lngInLngs;
	        break;
	      }
	    }
	  }
	  changeLanguage(lng, callback) {
	    var _this2 = this;
	    this.isLanguageChangingTo = lng;
	    const deferred = defer();
	    this.emit('languageChanging', lng);
	    const setLngProps = l => {
	      this.language = l;
	      this.languages = this.services.languageUtils.toResolveHierarchy(l);
	      this.resolvedLanguage = undefined;
	      this.setResolvedLanguage(l);
	    };
	    const done = (err, l) => {
	      if (l) {
	        setLngProps(l);
	        this.translator.changeLanguage(l);
	        this.isLanguageChangingTo = undefined;
	        this.emit('languageChanged', l);
	        this.logger.log('languageChanged', l);
	      } else {
	        this.isLanguageChangingTo = undefined;
	      }
	      deferred.resolve(function () {
	        return _this2.t(...arguments);
	      });
	      if (callback) callback(err, function () {
	        return _this2.t(...arguments);
	      });
	    };
	    const setLng = lngs => {
	      if (!lng && !lngs && this.services.languageDetector) lngs = [];
	      const l = isString(lngs) ? lngs : this.services.languageUtils.getBestMatchFromCodes(lngs);
	      if (l) {
	        if (!this.language) {
	          setLngProps(l);
	        }
	        if (!this.translator.language) this.translator.changeLanguage(l);
	        if (this.services.languageDetector && this.services.languageDetector.cacheUserLanguage) this.services.languageDetector.cacheUserLanguage(l);
	      }
	      this.loadResources(l, err => {
	        done(err, l);
	      });
	    };
	    if (!lng && this.services.languageDetector && !this.services.languageDetector.async) {
	      setLng(this.services.languageDetector.detect());
	    } else if (!lng && this.services.languageDetector && this.services.languageDetector.async) {
	      if (this.services.languageDetector.detect.length === 0) {
	        this.services.languageDetector.detect().then(setLng);
	      } else {
	        this.services.languageDetector.detect(setLng);
	      }
	    } else {
	      setLng(lng);
	    }
	    return deferred;
	  }
	  getFixedT(lng, ns, keyPrefix) {
	    var _this3 = this;
	    const fixedT = function (key, opts) {
	      let options;
	      if (typeof opts !== 'object') {
	        for (var _len3 = arguments.length, rest = new Array(_len3 > 2 ? _len3 - 2 : 0), _key3 = 2; _key3 < _len3; _key3++) {
	          rest[_key3 - 2] = arguments[_key3];
	        }
	        options = _this3.options.overloadTranslationOptionHandler([key, opts].concat(rest));
	      } else {
	        options = {
	          ...opts
	        };
	      }
	      options.lng = options.lng || fixedT.lng;
	      options.lngs = options.lngs || fixedT.lngs;
	      options.ns = options.ns || fixedT.ns;
	      if (options.keyPrefix !== '') options.keyPrefix = options.keyPrefix || keyPrefix || fixedT.keyPrefix;
	      const keySeparator = _this3.options.keySeparator || '.';
	      let resultKey;
	      if (options.keyPrefix && Array.isArray(key)) {
	        resultKey = key.map(k => `${options.keyPrefix}${keySeparator}${k}`);
	      } else {
	        resultKey = options.keyPrefix ? `${options.keyPrefix}${keySeparator}${key}` : key;
	      }
	      return _this3.t(resultKey, options);
	    };
	    if (isString(lng)) {
	      fixedT.lng = lng;
	    } else {
	      fixedT.lngs = lng;
	    }
	    fixedT.ns = ns;
	    fixedT.keyPrefix = keyPrefix;
	    return fixedT;
	  }
	  t() {
	    return this.translator && this.translator.translate(...arguments);
	  }
	  exists() {
	    return this.translator && this.translator.exists(...arguments);
	  }
	  setDefaultNamespace(ns) {
	    this.options.defaultNS = ns;
	  }
	  hasLoadedNamespace(ns) {
	    let options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};
	    if (!this.isInitialized) {
	      this.logger.warn('hasLoadedNamespace: i18next was not initialized', this.languages);
	      return false;
	    }
	    if (!this.languages || !this.languages.length) {
	      this.logger.warn('hasLoadedNamespace: i18n.languages were undefined or empty', this.languages);
	      return false;
	    }
	    const lng = options.lng || this.resolvedLanguage || this.languages[0];
	    const fallbackLng = this.options ? this.options.fallbackLng : false;
	    const lastLng = this.languages[this.languages.length - 1];
	    if (lng.toLowerCase() === 'cimode') return true;
	    const loadNotPending = (l, n) => {
	      const loadState = this.services.backendConnector.state[`${l}|${n}`];
	      return loadState === -1 || loadState === 0 || loadState === 2;
	    };
	    if (options.precheck) {
	      const preResult = options.precheck(this, loadNotPending);
	      if (preResult !== undefined) return preResult;
	    }
	    if (this.hasResourceBundle(lng, ns)) return true;
	    if (!this.services.backendConnector.backend || this.options.resources && !this.options.partialBundledLanguages) return true;
	    if (loadNotPending(lng, ns) && (!fallbackLng || loadNotPending(lastLng, ns))) return true;
	    return false;
	  }
	  loadNamespaces(ns, callback) {
	    const deferred = defer();
	    if (!this.options.ns) {
	      if (callback) callback();
	      return Promise.resolve();
	    }
	    if (isString(ns)) ns = [ns];
	    ns.forEach(n => {
	      if (this.options.ns.indexOf(n) < 0) this.options.ns.push(n);
	    });
	    this.loadResources(err => {
	      deferred.resolve();
	      if (callback) callback(err);
	    });
	    return deferred;
	  }
	  loadLanguages(lngs, callback) {
	    const deferred = defer();
	    if (isString(lngs)) lngs = [lngs];
	    const preloaded = this.options.preload || [];
	    const newLngs = lngs.filter(lng => preloaded.indexOf(lng) < 0 && this.services.languageUtils.isSupportedCode(lng));
	    if (!newLngs.length) {
	      if (callback) callback();
	      return Promise.resolve();
	    }
	    this.options.preload = preloaded.concat(newLngs);
	    this.loadResources(err => {
	      deferred.resolve();
	      if (callback) callback(err);
	    });
	    return deferred;
	  }
	  dir(lng) {
	    if (!lng) lng = this.resolvedLanguage || (this.languages && this.languages.length > 0 ? this.languages[0] : this.language);
	    if (!lng) return 'rtl';
	    const rtlLngs = ['ar', 'shu', 'sqr', 'ssh', 'xaa', 'yhd', 'yud', 'aao', 'abh', 'abv', 'acm', 'acq', 'acw', 'acx', 'acy', 'adf', 'ads', 'aeb', 'aec', 'afb', 'ajp', 'apc', 'apd', 'arb', 'arq', 'ars', 'ary', 'arz', 'auz', 'avl', 'ayh', 'ayl', 'ayn', 'ayp', 'bbz', 'pga', 'he', 'iw', 'ps', 'pbt', 'pbu', 'pst', 'prp', 'prd', 'ug', 'ur', 'ydd', 'yds', 'yih', 'ji', 'yi', 'hbo', 'men', 'xmn', 'fa', 'jpr', 'peo', 'pes', 'prs', 'dv', 'sam', 'ckb'];
	    const languageUtils = this.services && this.services.languageUtils || new LanguageUtil(get());
	    return rtlLngs.indexOf(languageUtils.getLanguagePartFromCode(lng)) > -1 || lng.toLowerCase().indexOf('-arab') > 1 ? 'rtl' : 'ltr';
	  }
	  static createInstance() {
	    let options = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
	    let callback = arguments.length > 1 ? arguments[1] : undefined;
	    return new I18n(options, callback);
	  }
	  cloneInstance() {
	    let options = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
	    let callback = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : noop$1;
	    const forkResourceStore = options.forkResourceStore;
	    if (forkResourceStore) delete options.forkResourceStore;
	    const mergedOptions = {
	      ...this.options,
	      ...options,
	      ...{
	        isClone: true
	      }
	    };
	    const clone = new I18n(mergedOptions);
	    if (options.debug !== undefined || options.prefix !== undefined) {
	      clone.logger = clone.logger.clone(options);
	    }
	    const membersToCopy = ['store', 'services', 'language'];
	    membersToCopy.forEach(m => {
	      clone[m] = this[m];
	    });
	    clone.services = {
	      ...this.services
	    };
	    clone.services.utils = {
	      hasLoadedNamespace: clone.hasLoadedNamespace.bind(clone)
	    };
	    if (forkResourceStore) {
	      clone.store = new ResourceStore(this.store.data, mergedOptions);
	      clone.services.resourceStore = clone.store;
	    }
	    clone.translator = new Translator(clone.services, mergedOptions);
	    clone.translator.on('*', function (event) {
	      for (var _len4 = arguments.length, args = new Array(_len4 > 1 ? _len4 - 1 : 0), _key4 = 1; _key4 < _len4; _key4++) {
	        args[_key4 - 1] = arguments[_key4];
	      }
	      clone.emit(event, ...args);
	    });
	    clone.init(mergedOptions, callback);
	    clone.translator.options = mergedOptions;
	    clone.translator.backendConnector.services.utils = {
	      hasLoadedNamespace: clone.hasLoadedNamespace.bind(clone)
	    };
	    return clone;
	  }
	  toJSON() {
	    return {
	      options: this.options,
	      store: this.store,
	      language: this.language,
	      languages: this.languages,
	      resolvedLanguage: this.resolvedLanguage
	    };
	  }
	}
	const instance = I18n.createInstance();
	instance.createInstance = I18n.createInstance;
	instance.createInstance;
	instance.dir;
	instance.init;
	instance.loadResources;
	instance.reloadResources;
	instance.use;
	instance.changeLanguage;
	instance.getFixedT;
	instance.t;
	instance.exists;
	instance.setDefaultNamespace;
	instance.hasLoadedNamespace;
	instance.loadNamespaces;
	instance.loadLanguages;

	function warn() {
	  if (console && console.warn) {
	    for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
	      args[_key] = arguments[_key];
	    }
	    if (typeof args[0] === 'string') args[0] = `react-i18next:: ${args[0]}`;
	    console.warn(...args);
	  }
	}
	const alreadyWarned = {};
	function warnOnce() {
	  for (var _len2 = arguments.length, args = new Array(_len2), _key2 = 0; _key2 < _len2; _key2++) {
	    args[_key2] = arguments[_key2];
	  }
	  if (typeof args[0] === 'string' && alreadyWarned[args[0]]) return;
	  if (typeof args[0] === 'string') alreadyWarned[args[0]] = new Date();
	  warn(...args);
	}
	const loadedClb = (i18n, cb) => () => {
	  if (i18n.isInitialized) {
	    cb();
	  } else {
	    const initialized = () => {
	      setTimeout(() => {
	        i18n.off('initialized', initialized);
	      }, 0);
	      cb();
	    };
	    i18n.on('initialized', initialized);
	  }
	};
	function loadNamespaces(i18n, ns, cb) {
	  i18n.loadNamespaces(ns, loadedClb(i18n, cb));
	}
	function loadLanguages(i18n, lng, ns, cb) {
	  if (typeof ns === 'string') ns = [ns];
	  ns.forEach(n => {
	    if (i18n.options.ns.indexOf(n) < 0) i18n.options.ns.push(n);
	  });
	  i18n.loadLanguages(lng, loadedClb(i18n, cb));
	}
	function oldI18nextHasLoadedNamespace(ns, i18n) {
	  let options = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : {};
	  const lng = i18n.languages[0];
	  const fallbackLng = i18n.options ? i18n.options.fallbackLng : false;
	  const lastLng = i18n.languages[i18n.languages.length - 1];
	  if (lng.toLowerCase() === 'cimode') return true;
	  const loadNotPending = (l, n) => {
	    const loadState = i18n.services.backendConnector.state[`${l}|${n}`];
	    return loadState === -1 || loadState === 2;
	  };
	  if (options.bindI18n && options.bindI18n.indexOf('languageChanging') > -1 && i18n.services.backendConnector.backend && i18n.isLanguageChangingTo && !loadNotPending(i18n.isLanguageChangingTo, ns)) return false;
	  if (i18n.hasResourceBundle(lng, ns)) return true;
	  if (!i18n.services.backendConnector.backend || i18n.options.resources && !i18n.options.partialBundledLanguages) return true;
	  if (loadNotPending(lng, ns) && (!fallbackLng || loadNotPending(lastLng, ns))) return true;
	  return false;
	}
	function hasLoadedNamespace(ns, i18n) {
	  let options = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : {};
	  if (!i18n.languages || !i18n.languages.length) {
	    warnOnce('i18n.languages were undefined or empty', i18n.languages);
	    return true;
	  }
	  const isNewerI18next = i18n.options.ignoreJSONStructure !== undefined;
	  if (!isNewerI18next) {
	    return oldI18nextHasLoadedNamespace(ns, i18n, options);
	  }
	  return i18n.hasLoadedNamespace(ns, {
	    lng: options.lng,
	    precheck: (i18nInstance, loadNotPending) => {
	      if (options.bindI18n && options.bindI18n.indexOf('languageChanging') > -1 && i18nInstance.services.backendConnector.backend && i18nInstance.isLanguageChangingTo && !loadNotPending(i18nInstance.isLanguageChangingTo, ns)) return false;
	    }
	  });
	}

	const matchHtmlEntity = /&(?:amp|#38|lt|#60|gt|#62|apos|#39|quot|#34|nbsp|#160|copy|#169|reg|#174|hellip|#8230|#x2F|#47);/g;
	const htmlEntities = {
	  '&amp;': '&',
	  '&#38;': '&',
	  '&lt;': '<',
	  '&#60;': '<',
	  '&gt;': '>',
	  '&#62;': '>',
	  '&apos;': "'",
	  '&#39;': "'",
	  '&quot;': '"',
	  '&#34;': '"',
	  '&nbsp;': ' ',
	  '&#160;': ' ',
	  '&copy;': '©',
	  '&#169;': '©',
	  '&reg;': '®',
	  '&#174;': '®',
	  '&hellip;': '…',
	  '&#8230;': '…',
	  '&#x2F;': '/',
	  '&#47;': '/'
	};
	const unescapeHtmlEntity = m => htmlEntities[m];
	const unescape = text => text.replace(matchHtmlEntity, unescapeHtmlEntity);

	let defaultOptions = {
	  bindI18n: 'languageChanged',
	  bindI18nStore: '',
	  transEmptyNodeValue: '',
	  transSupportBasicHtmlNodes: true,
	  transWrapTextNodes: '',
	  transKeepBasicHtmlNodesFor: ['br', 'strong', 'i', 'p'],
	  useSuspense: true,
	  unescape
	};
	function setDefaults() {
	  let options = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
	  defaultOptions = {
	    ...defaultOptions,
	    ...options
	  };
	}
	function getDefaults$2() {
	  return defaultOptions;
	}

	let i18nInstance;
	function setI18n(instance) {
	  i18nInstance = instance;
	}
	function getI18n() {
	  return i18nInstance;
	}

	const initReactI18next = {
	  type: '3rdParty',
	  init(instance) {
	    setDefaults(instance.options.react);
	    setI18n(instance);
	  }
	};

	const I18nContext = /*#__PURE__*/reactExports.createContext();
	class ReportNamespaces {
	  constructor() {
	    this.usedNamespaces = {};
	  }
	  addUsedNamespaces(namespaces) {
	    namespaces.forEach(ns => {
	      if (!this.usedNamespaces[ns]) this.usedNamespaces[ns] = true;
	    });
	  }
	  getUsedNamespaces() {
	    return Object.keys(this.usedNamespaces);
	  }
	}

	const usePrevious = (value, ignore) => {
	  const ref = reactExports.useRef();
	  reactExports.useEffect(() => {
	    ref.current = ignore ? ref.current : value;
	  }, [value, ignore]);
	  return ref.current;
	};
	function alwaysNewT(i18n, language, namespace, keyPrefix) {
	  return i18n.getFixedT(language, namespace, keyPrefix);
	}
	function useMemoizedT(i18n, language, namespace, keyPrefix) {
	  return reactExports.useCallback(alwaysNewT(i18n, language, namespace, keyPrefix), [i18n, language, namespace, keyPrefix]);
	}
	function useTranslation(ns) {
	  let props = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};
	  const {
	    i18n: i18nFromProps
	  } = props;
	  const {
	    i18n: i18nFromContext,
	    defaultNS: defaultNSFromContext
	  } = reactExports.useContext(I18nContext) || {};
	  const i18n = i18nFromProps || i18nFromContext || getI18n();
	  if (i18n && !i18n.reportNamespaces) i18n.reportNamespaces = new ReportNamespaces();
	  if (!i18n) {
	    warnOnce('You will need to pass in an i18next instance by using initReactI18next');
	    const notReadyT = (k, optsOrDefaultValue) => {
	      if (typeof optsOrDefaultValue === 'string') return optsOrDefaultValue;
	      if (optsOrDefaultValue && typeof optsOrDefaultValue === 'object' && typeof optsOrDefaultValue.defaultValue === 'string') return optsOrDefaultValue.defaultValue;
	      return Array.isArray(k) ? k[k.length - 1] : k;
	    };
	    const retNotReady = [notReadyT, {}, false];
	    retNotReady.t = notReadyT;
	    retNotReady.i18n = {};
	    retNotReady.ready = false;
	    return retNotReady;
	  }
	  if (i18n.options.react && i18n.options.react.wait !== undefined) warnOnce('It seems you are still using the old wait option, you may migrate to the new useSuspense behaviour.');
	  const i18nOptions = {
	    ...getDefaults$2(),
	    ...i18n.options.react,
	    ...props
	  };
	  const {
	    useSuspense,
	    keyPrefix
	  } = i18nOptions;
	  let namespaces = ns || defaultNSFromContext || i18n.options && i18n.options.defaultNS;
	  namespaces = typeof namespaces === 'string' ? [namespaces] : namespaces || ['translation'];
	  if (i18n.reportNamespaces.addUsedNamespaces) i18n.reportNamespaces.addUsedNamespaces(namespaces);
	  const ready = (i18n.isInitialized || i18n.initializedStoreOnce) && namespaces.every(n => hasLoadedNamespace(n, i18n, i18nOptions));
	  const memoGetT = useMemoizedT(i18n, props.lng || null, i18nOptions.nsMode === 'fallback' ? namespaces : namespaces[0], keyPrefix);
	  const getT = () => memoGetT;
	  const getNewT = () => alwaysNewT(i18n, props.lng || null, i18nOptions.nsMode === 'fallback' ? namespaces : namespaces[0], keyPrefix);
	  const [t, setT] = reactExports.useState(getT);
	  let joinedNS = namespaces.join();
	  if (props.lng) joinedNS = `${props.lng}${joinedNS}`;
	  const previousJoinedNS = usePrevious(joinedNS);
	  const isMounted = reactExports.useRef(true);
	  reactExports.useEffect(() => {
	    const {
	      bindI18n,
	      bindI18nStore
	    } = i18nOptions;
	    isMounted.current = true;
	    if (!ready && !useSuspense) {
	      if (props.lng) {
	        loadLanguages(i18n, props.lng, namespaces, () => {
	          if (isMounted.current) setT(getNewT);
	        });
	      } else {
	        loadNamespaces(i18n, namespaces, () => {
	          if (isMounted.current) setT(getNewT);
	        });
	      }
	    }
	    if (ready && previousJoinedNS && previousJoinedNS !== joinedNS && isMounted.current) {
	      setT(getNewT);
	    }
	    function boundReset() {
	      if (isMounted.current) setT(getNewT);
	    }
	    if (bindI18n && i18n) i18n.on(bindI18n, boundReset);
	    if (bindI18nStore && i18n) i18n.store.on(bindI18nStore, boundReset);
	    return () => {
	      isMounted.current = false;
	      if (bindI18n && i18n) bindI18n.split(' ').forEach(e => i18n.off(e, boundReset));
	      if (bindI18nStore && i18n) bindI18nStore.split(' ').forEach(e => i18n.store.off(e, boundReset));
	    };
	  }, [i18n, joinedNS]);
	  reactExports.useEffect(() => {
	    if (isMounted.current && ready) {
	      setT(getT);
	    }
	  }, [i18n, keyPrefix, ready]);
	  const ret = [t, i18n, ready];
	  ret.t = t;
	  ret.i18n = i18n;
	  ret.ready = ready;
	  if (ready) return ret;
	  if (!ready && !useSuspense) return ret;
	  throw new Promise(resolve => {
	    if (props.lng) {
	      loadLanguages(i18n, props.lng, namespaces, () => resolve());
	    } else {
	      loadNamespaces(i18n, namespaces, () => resolve());
	    }
	  });
	}

	//#region lib/utils.js
	const UNSAFE_KEYS$1 = ["__proto__", "constructor", "prototype"];
	function isSafeUrlSegmentBase(v) {
	  if (typeof v !== "string") return false;
	  if (v.length === 0 || v.length > 128) return false;
	  if (UNSAFE_KEYS$1.indexOf(v) > -1) return false;
	  if (v.indexOf("..") > -1) return false;
	  if (v.indexOf("\\") > -1) return false;
	  if (/[?#%\s@]/.test(v)) return false;
	  if (/[\x00-\x1F\x7F]/.test(v)) return false;
	  return true;
	}
	function isSafeLangUrlSegment(v) {
	  if (!isSafeUrlSegmentBase(v)) return false;
	  if (v.indexOf("/") > -1) return false;
	  return true;
	}
	function isSafeNsUrlSegment(v) {
	  return isSafeUrlSegmentBase(v);
	}
	const SAFETY_CHECK_BY_KEY = {
	  lng: isSafeLangUrlSegment,
	  ns: isSafeNsUrlSegment
	};
	function sanitizeLogValue(v) {
	  if (typeof v !== "string") return v;
	  return v.replace(/[\r\n\x00-\x1F\x7F]/g, " ");
	}
	function redactUrlCredentials(u) {
	  if (typeof u !== "string" || u.length === 0) return u;
	  try {
	    const parsed = new URL(u);
	    if (parsed.username || parsed.password) {
	      parsed.username = "";
	      parsed.password = "";
	      return parsed.toString();
	    }
	    return u;
	  } catch (e) {
	    return u.replace(/(\/\/)[^/@\s]+@/g, "$1");
	  }
	}
	function hasXMLHttpRequest() {
	  return typeof XMLHttpRequest === "function" || typeof XMLHttpRequest === "object";
	}
	/**
	* Determine whether the given `maybePromise` is a Promise.
	*
	* @param {*} maybePromise
	*
	* @returns {Boolean}
	*/
	function isPromise(maybePromise) {
	  return !!maybePromise && typeof maybePromise.then === "function";
	}
	/**
	* Convert any value to a Promise than will resolve to this value.
	*
	* @param {*} maybePromise
	*
	* @returns {Promise}
	*/
	function makePromise(maybePromise) {
	  if (isPromise(maybePromise)) return maybePromise;
	  return Promise.resolve(maybePromise);
	}
	const interpolationRegexp = /\{\{(.+?)\}\}/g;
	function interpolateUrl(str, data) {
	  let unsafe = false;
	  const result = str.replace(interpolationRegexp, (match, key) => {
	    const k = key.trim();
	    if (UNSAFE_KEYS$1.indexOf(k) > -1) return match;
	    const value = data[k];
	    if (value == null) return match;
	    const check = SAFETY_CHECK_BY_KEY[k] || isSafeLangUrlSegment;
	    const segments = String(value).split("+");
	    for (const seg of segments) if (!check(seg)) {
	      unsafe = true;
	      return match;
	    }
	    return segments.join("+");
	  });
	  return unsafe ? null : result;
	}
	//#endregion
	//#region lib/request.js
	const g$1 = typeof globalThis !== "undefined" ? globalThis : typeof global !== "undefined" ? global : typeof window !== "undefined" ? window : void 0;
	let fetchApi;
	if (typeof fetch === "function") fetchApi = fetch;else if (g$1 && typeof g$1.fetch === "function") fetchApi = g$1.fetch;
	const XmlHttpRequestApi = hasXMLHttpRequest() && g$1 ? g$1.XMLHttpRequest : void 0;
	const ActiveXObjectApi = typeof ActiveXObject === "function" && g$1 ? g$1.ActiveXObject : void 0;
	const UNSAFE_KEYS = ["__proto__", "constructor", "prototype"];
	const addQueryString = (url, params) => {
	  if (params && typeof params === "object") {
	    let queryString = "";
	    for (const paramName of Object.keys(params)) {
	      if (UNSAFE_KEYS.indexOf(paramName) > -1) continue;
	      queryString += "&" + encodeURIComponent(paramName) + "=" + encodeURIComponent(params[paramName]);
	    }
	    if (!queryString) return url;
	    url = url + (url.indexOf("?") !== -1 ? "&" : "?") + queryString.slice(1);
	  }
	  return url;
	};
	const fetchIt = (url, fetchOptions, callback, altFetch) => {
	  const resolver = response => {
	    if (!response.ok) return callback(response.statusText || "Error", {
	      status: response.status
	    });
	    response.text().then(data => {
	      callback(null, {
	        status: response.status,
	        data
	      });
	    }).catch(callback);
	  };
	  if (altFetch) {
	    const altResponse = altFetch(url, fetchOptions);
	    if (altResponse instanceof Promise) {
	      altResponse.then(resolver).catch(callback);
	      return;
	    }
	  }
	  if (typeof fetch === "function") fetch(url, fetchOptions).then(resolver).catch(callback);else fetchApi(url, fetchOptions).then(resolver).catch(callback);
	};
	const requestWithFetch = (options, url, payload, callback) => {
	  if (options.queryStringParams) url = addQueryString(url, options.queryStringParams);
	  const headers = {
	    ...(typeof options.customHeaders === "function" ? options.customHeaders() : options.customHeaders)
	  };
	  if (typeof window === "undefined" && typeof global !== "undefined" && typeof global.process !== "undefined" && global.process.versions && global.process.versions.node) headers["User-Agent"] = `i18next-http-backend (node/${global.process.version}; ${global.process.platform} ${global.process.arch})`;
	  if (payload) headers["Content-Type"] = "application/json";
	  const reqOptions = typeof options.requestOptions === "function" ? options.requestOptions(payload) : options.requestOptions;
	  const fetchOptions = {
	    method: payload ? "POST" : "GET",
	    body: payload ? options.stringify(payload) : void 0,
	    headers,
	    ...(options._omitFetchOptions ? {} : reqOptions)
	  };
	  const altFetch = typeof options.alternateFetch === "function" && options.alternateFetch.length >= 1 ? options.alternateFetch : void 0;
	  try {
	    fetchIt(url, fetchOptions, callback, altFetch);
	  } catch (e) {
	    if (!reqOptions || Object.keys(reqOptions).length === 0 || !e.message || e.message.indexOf("not implemented") < 0) return callback(e);
	    try {
	      Object.keys(reqOptions).forEach(opt => {
	        delete fetchOptions[opt];
	      });
	      fetchIt(url, fetchOptions, callback, altFetch);
	      options._omitFetchOptions = true;
	    } catch (err) {
	      callback(err);
	    }
	  }
	};
	const requestWithXmlHttpRequest = (options, url, payload, callback) => {
	  if (payload && typeof payload === "object") payload = addQueryString("", payload).slice(1);
	  if (options.queryStringParams) url = addQueryString(url, options.queryStringParams);
	  try {
	    const x = XmlHttpRequestApi ? new XmlHttpRequestApi() : new ActiveXObjectApi("MSXML2.XMLHTTP.3.0");
	    x.open(payload ? "POST" : "GET", url, 1);
	    if (!options.crossDomain) x.setRequestHeader("X-Requested-With", "XMLHttpRequest");
	    x.withCredentials = !!options.withCredentials;
	    if (payload) x.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
	    if (x.overrideMimeType) x.overrideMimeType("application/json");
	    let h = options.customHeaders;
	    h = typeof h === "function" ? h() : h;
	    if (h) for (const i of Object.keys(h)) {
	      if (UNSAFE_KEYS.indexOf(i) > -1) continue;
	      x.setRequestHeader(i, h[i]);
	    }
	    x.onreadystatechange = () => {
	      x.readyState > 3 && callback(x.status >= 400 ? x.statusText : null, {
	        status: x.status,
	        data: x.responseText
	      });
	    };
	    x.send(payload);
	  } catch (e) {
	    console && console.log(e);
	  }
	};
	const request = (options, url, payload, callback) => {
	  if (typeof payload === "function") {
	    callback = payload;
	    payload = void 0;
	  }
	  callback = callback || (() => {});
	  if (fetchApi && url.indexOf("file:") !== 0) return requestWithFetch(options, url, payload, callback);
	  if (hasXMLHttpRequest() || typeof ActiveXObject === "function") return requestWithXmlHttpRequest(options, url, payload, callback);
	  callback(/* @__PURE__ */new Error("No fetch and no xhr implementation found!"));
	};
	//#endregion
	//#region lib/index.js
	const getDefaults$1 = () => {
	  return {
	    loadPath: "/locales/{{lng}}/{{ns}}.json",
	    addPath: "/locales/add/{{lng}}/{{ns}}",
	    parse: data => JSON.parse(data),
	    stringify: JSON.stringify,
	    parsePayload: (namespace, key, fallbackValue) => ({
	      [key]: fallbackValue || ""
	    }),
	    parseLoadPayload: (languages, namespaces) => void 0,
	    request,
	    reloadInterval: typeof window !== "undefined" ? false : 3600 * 1e3,
	    customHeaders: {},
	    queryStringParams: {},
	    crossDomain: false,
	    withCredentials: false,
	    overrideMimeType: false,
	    requestOptions: {
	      mode: "cors",
	      credentials: "same-origin",
	      cache: "default"
	    }
	  };
	};
	var Backend = class {
	  constructor(services, options = {}, allOptions = {}) {
	    this.services = services;
	    this.options = options;
	    this.allOptions = allOptions;
	    this.type = "backend";
	    this.init(services, options, allOptions);
	  }
	  init(services, options = {}, allOptions = {}) {
	    this.services = services;
	    this.options = {
	      ...getDefaults$1(),
	      ...(this.options || {}),
	      ...options
	    };
	    this.allOptions = allOptions;
	    if (this.services && this.options.reloadInterval) {
	      const timer = setInterval(() => this.reload(), this.options.reloadInterval);
	      if (typeof timer === "object" && typeof timer.unref === "function") timer.unref();
	    }
	  }
	  readMulti(languages, namespaces, callback) {
	    this._readAny(languages, languages, namespaces, namespaces, callback);
	  }
	  read(language, namespace, callback) {
	    this._readAny([language], language, [namespace], namespace, callback);
	  }
	  _readAny(languages, loadUrlLanguages, namespaces, loadUrlNamespaces, callback) {
	    let loadPath = this.options.loadPath;
	    if (typeof this.options.loadPath === "function") loadPath = this.options.loadPath(languages, namespaces);
	    loadPath = makePromise(loadPath);
	    loadPath.then(resolvedLoadPath => {
	      if (!resolvedLoadPath) return callback(null, {});
	      const url = interpolateUrl(resolvedLoadPath, {
	        lng: languages.join("+"),
	        ns: namespaces.join("+")
	      });
	      if (url == null) {
	        const safeLngs = languages.map(sanitizeLogValue).join(", ");
	        const safeNss = namespaces.map(sanitizeLogValue).join(", ");
	        return callback(/* @__PURE__ */new Error("i18next-http-backend: unsafe lng/ns value — refusing to build request URL for languages=[" + safeLngs + "] namespaces=[" + safeNss + "]"), false);
	      }
	      this.loadUrl(url, callback, loadUrlLanguages, loadUrlNamespaces);
	    });
	  }
	  loadUrl(url, callback, languages, namespaces) {
	    const lng = typeof languages === "string" ? [languages] : languages;
	    const ns = typeof namespaces === "string" ? [namespaces] : namespaces;
	    const payload = this.options.parseLoadPayload(lng, ns);
	    const safeUrl = sanitizeLogValue(redactUrlCredentials(url));
	    this.options.request(this.options, url, payload, (err, res) => {
	      if (res && (res.status >= 500 && res.status < 600 || !res.status)) return callback("failed loading " + safeUrl + "; status code: " + res.status, true);
	      if (res && res.status >= 400 && res.status < 500) return callback("failed loading " + safeUrl + "; status code: " + res.status, false);
	      if (!res && err && err.message) {
	        const errorMessage = err.message.toLowerCase();
	        if (["failed", "fetch", "network", "load"].find(term => errorMessage.indexOf(term) > -1)) return callback("failed loading " + safeUrl + ": " + sanitizeLogValue(err.message), true);
	      }
	      if (err) return callback(err, false);
	      let ret, parseErr;
	      try {
	        if (typeof res.data === "string") ret = this.options.parse(res.data, languages, namespaces);else ret = res.data;
	      } catch (e) {
	        parseErr = "failed parsing " + safeUrl + " to json";
	      }
	      if (parseErr) return callback(parseErr, false);
	      callback(null, ret);
	    });
	  }
	  create(languages, namespace, key, fallbackValue, callback) {
	    if (!this.options.addPath) return;
	    if (typeof languages === "string") languages = [languages];
	    const payload = this.options.parsePayload(namespace, key, fallbackValue);
	    let finished = 0;
	    const dataArray = [];
	    const resArray = [];
	    languages.forEach(lng => {
	      let addPath = this.options.addPath;
	      if (typeof this.options.addPath === "function") addPath = this.options.addPath(lng, namespace);
	      const url = interpolateUrl(addPath, {
	        lng,
	        ns: namespace
	      });
	      if (url == null) {
	        finished += 1;
	        if (callback && finished === languages.length) callback(dataArray, resArray);
	        return;
	      }
	      this.options.request(this.options, url, payload, (data, res) => {
	        finished += 1;
	        dataArray.push(data);
	        resArray.push(res);
	        if (finished === languages.length) {
	          if (typeof callback === "function") callback(dataArray, resArray);
	        }
	      });
	    });
	  }
	  reload() {
	    const {
	      backendConnector,
	      languageUtils,
	      logger
	    } = this.services;
	    const currentLanguage = backendConnector.language;
	    if (currentLanguage && currentLanguage.toLowerCase() === "cimode") return;
	    const toLoad = [];
	    const append = lng => {
	      languageUtils.toResolveHierarchy(lng).forEach(l => {
	        if (toLoad.indexOf(l) < 0) toLoad.push(l);
	      });
	    };
	    append(currentLanguage);
	    if (this.allOptions.preload) this.allOptions.preload.forEach(l => append(l));
	    toLoad.forEach(lng => {
	      this.allOptions.ns.forEach(ns => {
	        backendConnector.read(lng, ns, "read", null, null, (err, data) => {
	          if (err) logger.warn(`loading namespace ${ns} for language ${lng} failed`, err);
	          if (!err && data) logger.log(`loaded namespace ${ns} for language ${lng}`, data);
	          backendConnector.loaded(`${lng}|${ns}`, err, data);
	        });
	      });
	    });
	  }
	};
	Backend.type = "backend";

	function _classCallCheck(a, n) {
	  if (!(a instanceof n)) throw new TypeError("Cannot call a class as a function");
	}

	function _defineProperties(e, r) {
	  for (var t = 0; t < r.length; t++) {
	    var o = r[t];
	    o.enumerable = o.enumerable || !1, o.configurable = !0, "value" in o && (o.writable = !0), Object.defineProperty(e, toPropertyKey(o.key), o);
	  }
	}
	function _createClass(e, r, t) {
	  return r && _defineProperties(e.prototype, r), t && _defineProperties(e, t), Object.defineProperty(e, "prototype", {
	    writable: !1
	  }), e;
	}

	var arr = [];
	var each = arr.forEach;
	var slice = arr.slice;
	function defaults(obj) {
	  each.call(slice.call(arguments, 1), function (source) {
	    if (source) {
	      for (var prop in source) {
	        if (obj[prop] === undefined) obj[prop] = source[prop];
	      }
	    }
	  });
	  return obj;
	}

	// eslint-disable-next-line no-control-regex
	var fieldContentRegExp = /^[\u0009\u0020-\u007e\u0080-\u00ff]+$/;
	var serializeCookie = function serializeCookie(name, val, options) {
	  var opt = options || {};
	  opt.path = opt.path || '/';
	  var value = encodeURIComponent(val);
	  var str = "".concat(name, "=").concat(value);
	  if (opt.maxAge > 0) {
	    var maxAge = opt.maxAge - 0;
	    if (Number.isNaN(maxAge)) throw new Error('maxAge should be a Number');
	    str += "; Max-Age=".concat(Math.floor(maxAge));
	  }
	  if (opt.domain) {
	    if (!fieldContentRegExp.test(opt.domain)) {
	      throw new TypeError('option domain is invalid');
	    }
	    str += "; Domain=".concat(opt.domain);
	  }
	  if (opt.path) {
	    if (!fieldContentRegExp.test(opt.path)) {
	      throw new TypeError('option path is invalid');
	    }
	    str += "; Path=".concat(opt.path);
	  }
	  if (opt.expires) {
	    if (typeof opt.expires.toUTCString !== 'function') {
	      throw new TypeError('option expires is invalid');
	    }
	    str += "; Expires=".concat(opt.expires.toUTCString());
	  }
	  if (opt.httpOnly) str += '; HttpOnly';
	  if (opt.secure) str += '; Secure';
	  if (opt.sameSite) {
	    var sameSite = typeof opt.sameSite === 'string' ? opt.sameSite.toLowerCase() : opt.sameSite;
	    switch (sameSite) {
	      case true:
	        str += '; SameSite=Strict';
	        break;
	      case 'lax':
	        str += '; SameSite=Lax';
	        break;
	      case 'strict':
	        str += '; SameSite=Strict';
	        break;
	      case 'none':
	        str += '; SameSite=None';
	        break;
	      default:
	        throw new TypeError('option sameSite is invalid');
	    }
	  }
	  return str;
	};
	var cookie = {
	  create: function create(name, value, minutes, domain) {
	    var cookieOptions = arguments.length > 4 && arguments[4] !== undefined ? arguments[4] : {
	      path: '/',
	      sameSite: 'strict'
	    };
	    if (minutes) {
	      cookieOptions.expires = new Date();
	      cookieOptions.expires.setTime(cookieOptions.expires.getTime() + minutes * 60 * 1000);
	    }
	    if (domain) cookieOptions.domain = domain;
	    document.cookie = serializeCookie(name, encodeURIComponent(value), cookieOptions);
	  },
	  read: function read(name) {
	    var nameEQ = "".concat(name, "=");
	    var ca = document.cookie.split(';');
	    for (var i = 0; i < ca.length; i++) {
	      var c = ca[i];
	      while (c.charAt(0) === ' ') c = c.substring(1, c.length);
	      if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
	    }
	    return null;
	  },
	  remove: function remove(name) {
	    this.create(name, '', -1);
	  }
	};
	var cookie$1 = {
	  name: 'cookie',
	  lookup: function lookup(options) {
	    var found;
	    if (options.lookupCookie && typeof document !== 'undefined') {
	      var c = cookie.read(options.lookupCookie);
	      if (c) found = c;
	    }
	    return found;
	  },
	  cacheUserLanguage: function cacheUserLanguage(lng, options) {
	    if (options.lookupCookie && typeof document !== 'undefined') {
	      cookie.create(options.lookupCookie, lng, options.cookieMinutes, options.cookieDomain, options.cookieOptions);
	    }
	  }
	};
	var querystring = {
	  name: 'querystring',
	  lookup: function lookup(options) {
	    var found;
	    if (typeof window !== 'undefined') {
	      var search = window.location.search;
	      if (!window.location.search && window.location.hash && window.location.hash.indexOf('?') > -1) {
	        search = window.location.hash.substring(window.location.hash.indexOf('?'));
	      }
	      var query = search.substring(1);
	      var params = query.split('&');
	      for (var i = 0; i < params.length; i++) {
	        var pos = params[i].indexOf('=');
	        if (pos > 0) {
	          var key = params[i].substring(0, pos);
	          if (key === options.lookupQuerystring) {
	            found = params[i].substring(pos + 1);
	          }
	        }
	      }
	    }
	    return found;
	  }
	};
	var hasLocalStorageSupport = null;
	var localStorageAvailable = function localStorageAvailable() {
	  if (hasLocalStorageSupport !== null) return hasLocalStorageSupport;
	  try {
	    hasLocalStorageSupport = window !== 'undefined' && window.localStorage !== null;
	    var testKey = 'i18next.translate.boo';
	    window.localStorage.setItem(testKey, 'foo');
	    window.localStorage.removeItem(testKey);
	  } catch (e) {
	    hasLocalStorageSupport = false;
	  }
	  return hasLocalStorageSupport;
	};
	var localStorage = {
	  name: 'localStorage',
	  lookup: function lookup(options) {
	    var found;
	    if (options.lookupLocalStorage && localStorageAvailable()) {
	      var lng = window.localStorage.getItem(options.lookupLocalStorage);
	      if (lng) found = lng;
	    }
	    return found;
	  },
	  cacheUserLanguage: function cacheUserLanguage(lng, options) {
	    if (options.lookupLocalStorage && localStorageAvailable()) {
	      window.localStorage.setItem(options.lookupLocalStorage, lng);
	    }
	  }
	};
	var hasSessionStorageSupport = null;
	var sessionStorageAvailable = function sessionStorageAvailable() {
	  if (hasSessionStorageSupport !== null) return hasSessionStorageSupport;
	  try {
	    hasSessionStorageSupport = window !== 'undefined' && window.sessionStorage !== null;
	    var testKey = 'i18next.translate.boo';
	    window.sessionStorage.setItem(testKey, 'foo');
	    window.sessionStorage.removeItem(testKey);
	  } catch (e) {
	    hasSessionStorageSupport = false;
	  }
	  return hasSessionStorageSupport;
	};
	var sessionStorage = {
	  name: 'sessionStorage',
	  lookup: function lookup(options) {
	    var found;
	    if (options.lookupSessionStorage && sessionStorageAvailable()) {
	      var lng = window.sessionStorage.getItem(options.lookupSessionStorage);
	      if (lng) found = lng;
	    }
	    return found;
	  },
	  cacheUserLanguage: function cacheUserLanguage(lng, options) {
	    if (options.lookupSessionStorage && sessionStorageAvailable()) {
	      window.sessionStorage.setItem(options.lookupSessionStorage, lng);
	    }
	  }
	};
	var navigator$1 = {
	  name: 'navigator',
	  lookup: function lookup(options) {
	    var found = [];
	    if (typeof navigator !== 'undefined') {
	      if (navigator.languages) {
	        // chrome only; not an array, so can't use .push.apply instead of iterating
	        for (var i = 0; i < navigator.languages.length; i++) {
	          found.push(navigator.languages[i]);
	        }
	      }
	      if (navigator.userLanguage) {
	        found.push(navigator.userLanguage);
	      }
	      if (navigator.language) {
	        found.push(navigator.language);
	      }
	    }
	    return found.length > 0 ? found : undefined;
	  }
	};
	var htmlTag = {
	  name: 'htmlTag',
	  lookup: function lookup(options) {
	    var found;
	    var htmlTag = options.htmlTag || (typeof document !== 'undefined' ? document.documentElement : null);
	    if (htmlTag && typeof htmlTag.getAttribute === 'function') {
	      found = htmlTag.getAttribute('lang');
	    }
	    return found;
	  }
	};
	var path = {
	  name: 'path',
	  lookup: function lookup(options) {
	    var found;
	    if (typeof window !== 'undefined') {
	      var language = window.location.pathname.match(/\/([a-zA-Z-]*)/g);
	      if (language instanceof Array) {
	        if (typeof options.lookupFromPathIndex === 'number') {
	          if (typeof language[options.lookupFromPathIndex] !== 'string') {
	            return undefined;
	          }
	          found = language[options.lookupFromPathIndex].replace('/', '');
	        } else {
	          found = language[0].replace('/', '');
	        }
	      }
	    }
	    return found;
	  }
	};
	var subdomain = {
	  name: 'subdomain',
	  lookup: function lookup(options) {
	    // If given get the subdomain index else 1
	    var lookupFromSubdomainIndex = typeof options.lookupFromSubdomainIndex === 'number' ? options.lookupFromSubdomainIndex + 1 : 1;
	    // get all matches if window.location. is existing
	    // first item of match is the match itself and the second is the first group macht which sould be the first subdomain match
	    // is the hostname no public domain get the or option of localhost
	    var language = typeof window !== 'undefined' && window.location && window.location.hostname && window.location.hostname.match(/^(\w{2,5})\.(([a-z0-9-]{1,63}\.[a-z]{2,6})|localhost)/i);

	    // if there is no match (null) return undefined
	    if (!language) return undefined;
	    // return the given group match
	    return language[lookupFromSubdomainIndex];
	  }
	};
	function getDefaults() {
	  return {
	    order: ['querystring', 'cookie', 'localStorage', 'sessionStorage', 'navigator', 'htmlTag'],
	    lookupQuerystring: 'lng',
	    lookupCookie: 'i18next',
	    lookupLocalStorage: 'i18nextLng',
	    lookupSessionStorage: 'i18nextLng',
	    // cache user language
	    caches: ['localStorage'],
	    excludeCacheFor: ['cimode'],
	    // cookieMinutes: 10,
	    // cookieDomain: 'myDomain'

	    convertDetectedLanguage: function convertDetectedLanguage(l) {
	      return l;
	    }
	  };
	}
	var Browser = /*#__PURE__*/function () {
	  function Browser(services) {
	    var options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};
	    _classCallCheck(this, Browser);
	    this.type = 'languageDetector';
	    this.detectors = {};
	    this.init(services, options);
	  }
	  _createClass(Browser, [{
	    key: "init",
	    value: function init(services) {
	      var options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};
	      var i18nOptions = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : {};
	      this.services = services || {
	        languageUtils: {}
	      }; // this way the language detector can be used without i18next
	      this.options = defaults(options, this.options || {}, getDefaults());
	      if (typeof this.options.convertDetectedLanguage === 'string' && this.options.convertDetectedLanguage.indexOf('15897') > -1) {
	        this.options.convertDetectedLanguage = function (l) {
	          return l.replace('-', '_');
	        };
	      }

	      // backwards compatibility
	      if (this.options.lookupFromUrlIndex) this.options.lookupFromPathIndex = this.options.lookupFromUrlIndex;
	      this.i18nOptions = i18nOptions;
	      this.addDetector(cookie$1);
	      this.addDetector(querystring);
	      this.addDetector(localStorage);
	      this.addDetector(sessionStorage);
	      this.addDetector(navigator$1);
	      this.addDetector(htmlTag);
	      this.addDetector(path);
	      this.addDetector(subdomain);
	    }
	  }, {
	    key: "addDetector",
	    value: function addDetector(detector) {
	      this.detectors[detector.name] = detector;
	      return this;
	    }
	  }, {
	    key: "detect",
	    value: function detect(detectionOrder) {
	      var _this = this;
	      if (!detectionOrder) detectionOrder = this.options.order;
	      var detected = [];
	      detectionOrder.forEach(function (detectorName) {
	        if (_this.detectors[detectorName]) {
	          var lookup = _this.detectors[detectorName].lookup(_this.options);
	          if (lookup && typeof lookup === 'string') lookup = [lookup];
	          if (lookup) detected = detected.concat(lookup);
	        }
	      });
	      detected = detected.map(function (d) {
	        return _this.options.convertDetectedLanguage(d);
	      });
	      if (this.services.languageUtils.getBestMatchFromCodes) return detected; // new i18next v19.5.0
	      return detected.length > 0 ? detected[0] : null; // a little backward compatibility
	    }
	  }, {
	    key: "cacheUserLanguage",
	    value: function cacheUserLanguage(lng, caches) {
	      var _this2 = this;
	      if (!caches) caches = this.options.caches;
	      if (!caches) return;
	      if (this.options.excludeCacheFor && this.options.excludeCacheFor.indexOf(lng) > -1) return;
	      caches.forEach(function (cacheName) {
	        if (_this2.detectors[cacheName]) _this2.detectors[cacheName].cacheUserLanguage(lng, _this2.options);
	      });
	    }
	  }]);
	  return Browser;
	}();
	Browser.type = 'languageDetector';

	// psgi.js (loaded before this bundle) defines these globals. Fall back to
	// sensible defaults so the tests, which do not load psgi.js, still work.
	var staticPrefix = window.staticPrefix || "/static/";
	var availableLanguages = window.availableLanguages;
	instance
	    .use(initReactI18next)
	    .use(Backend)
	    // Pick the language like the legacy manager does: the "llnglanguage" cookie
	    // first (so a language chosen in either interface is kept across a switch),
	    // then the browser languages, then English.
	    .use(Browser)
	    .init({
	    fallbackLng: "en",
	    supportedLngs: Array.isArray(availableLanguages)
	        ? availableLanguages
	        : undefined,
	    // Match "fr" for a "fr-FR" browser locale, as the legacy manager did
	    load: "languageOnly",
	    nonExplicitSupportedLngs: true,
	    detection: {
	        order: ["cookie", "navigator"],
	        lookupCookie: "llnglanguage",
	        // Persist the choice in the same cookie the legacy manager reads
	        caches: ["cookie"],
	        cookieMinutes: 365 * 24 * 60,
	    },
	    backend: {
	        // Served from the deployment's static directory, not a hardcoded /static
	        loadPath: "".concat(staticPrefix, "languages/{{lng}}.json"),
	    },
	});

	var reportWebVitals = function (onPerfEntry) {
	    if (onPerfEntry && onPerfEntry instanceof Function) {
	        Promise.resolve().then(function () { return webVitals; }).then(function (_a) {
	            var getCLS = _a.getCLS, getFID = _a.getFID, getFCP = _a.getFCP, getLCP = _a.getLCP, getTTFB = _a.getTTFB;
	            getCLS(onPerfEntry);
	            getFID(onPerfEntry);
	            getFCP(onPerfEntry);
	            getLCP(onPerfEntry);
	            getTTFB(onPerfEntry);
	        });
	    }
	};

	/******************************************************************************
	Copyright (c) Microsoft Corporation.

	Permission to use, copy, modify, and/or distribute this software for any
	purpose with or without fee is hereby granted.

	THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
	REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
	AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
	INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
	LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
	OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
	PERFORMANCE OF THIS SOFTWARE.
	***************************************************************************** */
	/* global Reflect, Promise, SuppressedError, Symbol */

	var __assign = function () {
	  __assign = Object.assign || function __assign(t) {
	    for (var s, i = 1, n = arguments.length; i < n; i++) {
	      s = arguments[i];
	      for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p)) t[p] = s[p];
	    }
	    return t;
	  };
	  return __assign.apply(this, arguments);
	};
	function __awaiter(thisArg, _arguments, P, generator) {
	  function adopt(value) {
	    return value instanceof P ? value : new P(function (resolve) {
	      resolve(value);
	    });
	  }
	  return new (P || (P = Promise))(function (resolve, reject) {
	    function fulfilled(value) {
	      try {
	        step(generator.next(value));
	      } catch (e) {
	        reject(e);
	      }
	    }
	    function rejected(value) {
	      try {
	        step(generator["throw"](value));
	      } catch (e) {
	        reject(e);
	      }
	    }
	    function step(result) {
	      result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
	    }
	    step((generator = generator.apply(thisArg, _arguments || [])).next());
	  });
	}
	function __generator(thisArg, body) {
	  var _ = {
	      label: 0,
	      sent: function () {
	        if (t[0] & 1) throw t[1];
	        return t[1];
	      },
	      trys: [],
	      ops: []
	    },
	    f,
	    y,
	    t,
	    g;
	  return g = {
	    next: verb(0),
	    "throw": verb(1),
	    "return": verb(2)
	  }, typeof Symbol === "function" && (g[Symbol.iterator] = function () {
	    return this;
	  }), g;
	  function verb(n) {
	    return function (v) {
	      return step([n, v]);
	    };
	  }
	  function step(op) {
	    if (f) throw new TypeError("Generator is already executing.");
	    while (g && (g = 0, op[0] && (_ = 0)), _) try {
	      if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
	      if (y = 0, t) op = [op[0] & 2, t.value];
	      switch (op[0]) {
	        case 0:
	        case 1:
	          t = op;
	          break;
	        case 4:
	          _.label++;
	          return {
	            value: op[1],
	            done: false
	          };
	        case 5:
	          _.label++;
	          y = op[1];
	          op = [0];
	          continue;
	        case 7:
	          op = _.ops.pop();
	          _.trys.pop();
	          continue;
	        default:
	          if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) {
	            _ = 0;
	            continue;
	          }
	          if (op[0] === 3 && (!t || op[1] > t[0] && op[1] < t[3])) {
	            _.label = op[1];
	            break;
	          }
	          if (op[0] === 6 && _.label < t[1]) {
	            _.label = t[1];
	            t = op;
	            break;
	          }
	          if (t && _.label < t[2]) {
	            _.label = t[2];
	            _.ops.push(op);
	            break;
	          }
	          if (t[2]) _.ops.pop();
	          _.trys.pop();
	          continue;
	      }
	      op = body.call(thisArg, _);
	    } catch (e) {
	      op = [6, e];
	      y = 0;
	    } finally {
	      f = t = 0;
	    }
	    if (op[0] & 5) throw op[1];
	    return {
	      value: op[0] ? op[1] : void 0,
	      done: true
	    };
	  }
	}
	typeof SuppressedError === "function" ? SuppressedError : function (error, suppressed, message) {
	  var e = new Error(message);
	  return e.name = "SuppressedError", e.error = error, e.suppressed = suppressed, e;
	};

	// Authentication helpers.
	//
	// LemonLDAP::NG protects the manager backend with a handler that, for an
	// unauthenticated Ajax request (Accept: application/json), returns a real
	// 401 with a "WWW-Authenticate: SSO <portal>" header instead of a 302 to the
	// portal. The legacy AngularJS manager caught that 401 on *every* Ajax
	// request and redirected the browser to the portal. This module reproduces
	// that behaviour for the React manager through a global `fetch` interceptor.
	// Redirect the browser to the portal for authentication, keeping the current
	// URL (base64 encoded) so the user comes back here after login.
	var goToPortal = function (portal) {
	    var target = portal || window.portal;
	    if (target) {
	        window.location.href =
	            "".concat(target, "?url=") + encodeURIComponent(window.btoa(window.location.href));
	    }
	};
	// Extract the portal URL from a "WWW-Authenticate: SSO <portal>" header.
	var portalFromResponse = function (response) {
	    var header = response.headers.get("WWW-Authenticate");
	    var match = header ? /^SSO\s+(\S+)/.exec(header) : null;
	    return match ? match[1] : undefined;
	};
	// Guard so that concurrent 401 responses trigger a single redirection.
	var redirecting = false;
	// Redirect to the portal when the response denotes an unauthenticated request
	// (401 with a "WWW-Authenticate: SSO <portal>" header, or any 401 when the
	// portal URL is already known). Returns true when a redirection was triggered.
	var handleUnauthorized = function (response) {
	    if (response.status !== 401)
	        return false;
	    var portal = portalFromResponse(response);
	    if (!portal && !window.portal)
	        return false;
	    if (!redirecting) {
	        redirecting = true;
	        goToPortal(portal);
	    }
	    return true;
	};
	// Install a global `fetch` interceptor that:
	//  - advertises a JSON-capable client (Accept: application/json) so the
	//    server answers protected requests with a real 401 instead of a 302
	//    redirect that `fetch` would silently follow to the portal login page;
	//  - redirects to the portal on such a 401, like the legacy interceptor did
	//    for every Ajax request.
	var installFetchInterceptor = function () {
	    if (window.__llngFetchInterceptor)
	        return;
	    window.__llngFetchInterceptor = true;
	    var nativeFetch = window.fetch.bind(window);
	    window.fetch = function (input, init) { return __awaiter(void 0, void 0, void 0, function () {
	        var base, headers, response;
	        var _a;
	        return __generator(this, function (_b) {
	            switch (_b.label) {
	                case 0:
	                    base = (_a = init === null || init === void 0 ? void 0 : init.headers) !== null && _a !== void 0 ? _a : (input instanceof Request ? input.headers : undefined);
	                    headers = new Headers(base);
	                    if (!headers.has("Accept"))
	                        headers.set("Accept", "application/json");
	                    return [4 /*yield*/, nativeFetch(input, __assign(__assign({}, init), { headers: headers }))];
	                case 1:
	                    response = _b.sent();
	                    handleUnauthorized(response);
	                    return [2 /*return*/, response];
	            }
	        });
	    }); };
	};

	var theme = createTheme({
	    palette: {
	        primary: orange$1,
	        secondary: {
	            main: grey$1[800],
	            dark: grey$1[900],
	            light: grey$1[500],
	        },
	        success: green$1,
	        warning: yellow$1,
	    },
	});
	function mountApp(children) {
	    // Handle a 401 (WWW-Authenticate: SSO <portal>) on any Ajax request by
	    // redirecting to the portal, like the legacy AngularJS $lmhttp interceptor.
	    installFetchInterceptor();
	    var container = document.getElementById("root");
	    var root = clientExports.createRoot(container);
	    var renderApp = function () {
	        root.render(jsxRuntimeExports.jsx(ThemeProvider, { theme: theme, children: jsxRuntimeExports.jsx(StyledEngineProvider, { injectFirst: true, children: jsxRuntimeExports.jsx(React.StrictMode, { children: children }) }) }));
	        reportWebVitals();
	    };
	    // psgi.js is loaded by a <script> tag placed before this bundle in the
	    // template, so its globals are already set here. It used to be fetched and
	    // injected as an inline script, which a strict Content-Security-Policy
	    // forbids: its content is dynamic, so no hash can cover it.
	    renderApp();
	}

	var ChevronLeft$1 = {};

	var createSvgIcon$1 = {};

	function getSvgIconUtilityClass(slot) {
	  return generateUtilityClass('MuiSvgIcon', slot);
	}
	generateUtilityClasses('MuiSvgIcon', ['root', 'colorPrimary', 'colorSecondary', 'colorAction', 'colorError', 'colorDisabled', 'fontSizeInherit', 'fontSizeSmall', 'fontSizeMedium', 'fontSizeLarge']);

	const _excluded$n = ["children", "className", "color", "component", "fontSize", "htmlColor", "inheritViewBox", "titleAccess", "viewBox"];
	const useUtilityClasses$h = ownerState => {
	  const {
	    color,
	    fontSize,
	    classes
	  } = ownerState;
	  const slots = {
	    root: ['root', color !== 'inherit' && `color${capitalize$2(color)}`, `fontSize${capitalize$2(fontSize)}`]
	  };
	  return composeClasses(slots, getSvgIconUtilityClass, classes);
	};
	const SvgIconRoot = styled$1('svg', {
	  name: 'MuiSvgIcon',
	  slot: 'Root',
	  overridesResolver: (props, styles) => {
	    const {
	      ownerState
	    } = props;
	    return [styles.root, ownerState.color !== 'inherit' && styles[`color${capitalize$2(ownerState.color)}`], styles[`fontSize${capitalize$2(ownerState.fontSize)}`]];
	  }
	})(({
	  theme,
	  ownerState
	}) => {
	  var _theme$transitions, _theme$transitions$cr, _theme$transitions2, _theme$typography, _theme$typography$pxT, _theme$typography2, _theme$typography2$px, _theme$typography3, _theme$typography3$px, _palette$ownerState$c, _palette, _palette2, _palette3;
	  return {
	    userSelect: 'none',
	    width: '1em',
	    height: '1em',
	    display: 'inline-block',
	    // the <svg> will define the property that has `currentColor`
	    // for example heroicons uses fill="none" and stroke="currentColor"
	    fill: ownerState.hasSvgAsChild ? undefined : 'currentColor',
	    flexShrink: 0,
	    transition: (_theme$transitions = theme.transitions) == null || (_theme$transitions$cr = _theme$transitions.create) == null ? void 0 : _theme$transitions$cr.call(_theme$transitions, 'fill', {
	      duration: (_theme$transitions2 = theme.transitions) == null || (_theme$transitions2 = _theme$transitions2.duration) == null ? void 0 : _theme$transitions2.shorter
	    }),
	    fontSize: {
	      inherit: 'inherit',
	      small: ((_theme$typography = theme.typography) == null || (_theme$typography$pxT = _theme$typography.pxToRem) == null ? void 0 : _theme$typography$pxT.call(_theme$typography, 20)) || '1.25rem',
	      medium: ((_theme$typography2 = theme.typography) == null || (_theme$typography2$px = _theme$typography2.pxToRem) == null ? void 0 : _theme$typography2$px.call(_theme$typography2, 24)) || '1.5rem',
	      large: ((_theme$typography3 = theme.typography) == null || (_theme$typography3$px = _theme$typography3.pxToRem) == null ? void 0 : _theme$typography3$px.call(_theme$typography3, 35)) || '2.1875rem'
	    }[ownerState.fontSize],
	    // TODO v5 deprecate, v6 remove for sx
	    color: (_palette$ownerState$c = (_palette = (theme.vars || theme).palette) == null || (_palette = _palette[ownerState.color]) == null ? void 0 : _palette.main) != null ? _palette$ownerState$c : {
	      action: (_palette2 = (theme.vars || theme).palette) == null || (_palette2 = _palette2.action) == null ? void 0 : _palette2.active,
	      disabled: (_palette3 = (theme.vars || theme).palette) == null || (_palette3 = _palette3.action) == null ? void 0 : _palette3.disabled,
	      inherit: undefined
	    }[ownerState.color]
	  };
	});
	const SvgIcon = /*#__PURE__*/reactExports.forwardRef(function SvgIcon(inProps, ref) {
	  const props = useThemeProps({
	    props: inProps,
	    name: 'MuiSvgIcon'
	  });
	  const {
	      children,
	      className,
	      color = 'inherit',
	      component = 'svg',
	      fontSize = 'medium',
	      htmlColor,
	      inheritViewBox = false,
	      titleAccess,
	      viewBox = '0 0 24 24'
	    } = props,
	    other = _objectWithoutPropertiesLoose(props, _excluded$n);
	  const hasSvgAsChild = /*#__PURE__*/ /*#__PURE__*/reactExports.isValidElement(children) && children.type === 'svg';
	  const ownerState = _extends$1({}, props, {
	    color,
	    component,
	    fontSize,
	    instanceFontSize: inProps.fontSize,
	    inheritViewBox,
	    viewBox,
	    hasSvgAsChild
	  });
	  const more = {};
	  if (!inheritViewBox) {
	    more.viewBox = viewBox;
	  }
	  const classes = useUtilityClasses$h(ownerState);
	  return /*#__PURE__*/jsxRuntimeExports.jsxs(SvgIconRoot, _extends$1({
	    as: component,
	    className: clsx(classes.root, className),
	    focusable: "false",
	    color: htmlColor,
	    "aria-hidden": titleAccess ? undefined : true,
	    role: titleAccess ? 'img' : undefined,
	    ref: ref
	  }, more, other, hasSvgAsChild && children.props, {
	    ownerState: ownerState,
	    children: [hasSvgAsChild ? children.props.children : children, titleAccess ? /*#__PURE__*/jsxRuntimeExports.jsx("title", {
	      children: titleAccess
	    }) : null]
	  }));
	});
	SvgIcon.muiName = 'SvgIcon';
	var SvgIcon$1 = SvgIcon;

	function createSvgIcon(path, displayName) {
	  function Component(props, ref) {
	    return /*#__PURE__*/jsxRuntimeExports.jsx(SvgIcon$1, _extends$1({
	      "data-testid": `${displayName}Icon`,
	      ref: ref
	    }, props, {
	      children: path
	    }));
	  }
	  Component.muiName = SvgIcon$1.muiName;
	  return /*#__PURE__*/reactExports.memo(/*#__PURE__*/reactExports.forwardRef(Component));
	}

	// TODO: remove this export once ClassNameGenerator is stable
	// eslint-disable-next-line @typescript-eslint/naming-convention
	const unstable_ClassNameGenerator = {
	  configure: generator => {
	    ClassNameGenerator$1.configure(generator);
	  }
	};

	var utils = /*#__PURE__*/Object.freeze({
		__proto__: null,
		capitalize: capitalize$2,
		createChainedFunction: createChainedFunction,
		createSvgIcon: createSvgIcon,
		debounce: debounce,
		deprecatedPropType: deprecatedPropType,
		isMuiElement: isMuiElement,
		ownerDocument: ownerDocument,
		ownerWindow: ownerWindow,
		requirePropFactory: requirePropFactory,
		setRef: setRef,
		unstable_ClassNameGenerator: unstable_ClassNameGenerator,
		unstable_useEnhancedEffect: useEnhancedEffect$1,
		unstable_useId: useId,
		unsupportedProp: unsupportedProp,
		useControlled: useControlled,
		useEventCallback: useEventCallback,
		useForkRef: useForkRef,
		useIsFocusVisible: useIsFocusVisible
	});

	var require$$0 = /*@__PURE__*/getAugmentedNamespace(utils);

	var hasRequiredCreateSvgIcon;

	function requireCreateSvgIcon () {
		if (hasRequiredCreateSvgIcon) return createSvgIcon$1;
		hasRequiredCreateSvgIcon = 1;
		(function (exports) {
			'use client';

			Object.defineProperty(exports, "__esModule", {
			  value: true
			});
			Object.defineProperty(exports, "default", {
			  enumerable: true,
			  get: function () {
			    return _utils.createSvgIcon;
			  }
			});
			var _utils = require$$0; 
		} (createSvgIcon$1));
		return createSvgIcon$1;
	}

	var hasRequiredChevronLeft;

	function requireChevronLeft () {
		if (hasRequiredChevronLeft) return ChevronLeft$1;
		hasRequiredChevronLeft = 1;

		var _interopRequireDefault = requireInteropRequireDefault();
		Object.defineProperty(ChevronLeft$1, "__esModule", {
		  value: true
		});
		ChevronLeft$1.default = void 0;
		var _createSvgIcon = _interopRequireDefault(/*@__PURE__*/ requireCreateSvgIcon());
		var _jsxRuntime = requireJsxRuntime();
		ChevronLeft$1.default = (0, _createSvgIcon.default)(/*#__PURE__*/(0, _jsxRuntime.jsx)("path", {
		  d: "M15.41 7.41 14 6l-6 6 6 6 1.41-1.41L10.83 12z"
		}), 'ChevronLeft');
		return ChevronLeft$1;
	}

	var ChevronLeftExports = /*@__PURE__*/ requireChevronLeft();
	var ChevronLeft = /*@__PURE__*/getDefaultExportFromCjs(ChevronLeftExports);

	var Menu$2 = {};

	var hasRequiredMenu;

	function requireMenu () {
		if (hasRequiredMenu) return Menu$2;
		hasRequiredMenu = 1;

		var _interopRequireDefault = requireInteropRequireDefault();
		Object.defineProperty(Menu$2, "__esModule", {
		  value: true
		});
		Menu$2.default = void 0;
		var _createSvgIcon = _interopRequireDefault(/*@__PURE__*/ requireCreateSvgIcon());
		var _jsxRuntime = requireJsxRuntime();
		Menu$2.default = (0, _createSvgIcon.default)(/*#__PURE__*/(0, _jsxRuntime.jsx)("path", {
		  d: "M3 18h18v-2H3zm0-5h18v-2H3zm0-7v2h18V6z"
		}), 'Menu');
		return Menu$2;
	}

	var MenuExports = /*@__PURE__*/ requireMenu();
	var MenuIcon = /*@__PURE__*/getDefaultExportFromCjs(MenuExports);

	var SettingsOutlined = {};

	var hasRequiredSettingsOutlined;

	function requireSettingsOutlined () {
		if (hasRequiredSettingsOutlined) return SettingsOutlined;
		hasRequiredSettingsOutlined = 1;

		var _interopRequireDefault = requireInteropRequireDefault();
		Object.defineProperty(SettingsOutlined, "__esModule", {
		  value: true
		});
		SettingsOutlined.default = void 0;
		var _createSvgIcon = _interopRequireDefault(/*@__PURE__*/ requireCreateSvgIcon());
		var _jsxRuntime = requireJsxRuntime();
		SettingsOutlined.default = (0, _createSvgIcon.default)(/*#__PURE__*/(0, _jsxRuntime.jsx)("path", {
		  d: "M19.43 12.98c.04-.32.07-.64.07-.98 0-.34-.03-.66-.07-.98l2.11-1.65c.19-.15.24-.42.12-.64l-2-3.46c-.09-.16-.26-.25-.44-.25-.06 0-.12.01-.17.03l-2.49 1c-.52-.4-1.08-.73-1.69-.98l-.38-2.65C14.46 2.18 14.25 2 14 2h-4c-.25 0-.46.18-.49.42l-.38 2.65c-.61.25-1.17.59-1.69.98l-2.49-1c-.06-.02-.12-.03-.18-.03-.17 0-.34.09-.43.25l-2 3.46c-.13.22-.07.49.12.64l2.11 1.65c-.04.32-.07.65-.07.98 0 .33.03.66.07.98l-2.11 1.65c-.19.15-.24.42-.12.64l2 3.46c.09.16.26.25.44.25.06 0 .12-.01.17-.03l2.49-1c.52.4 1.08.73 1.69.98l.38 2.65c.03.24.24.42.49.42h4c.25 0 .46-.18.49-.42l.38-2.65c.61-.25 1.17-.59 1.69-.98l2.49 1c.06.02.12.03.18.03.17 0 .34-.09.43-.25l2-3.46c.12-.22.07-.49-.12-.64zm-1.98-1.71c.04.31.05.52.05.73 0 .21-.02.43-.05.73l-.14 1.13.89.7 1.08.84-.7 1.21-1.27-.51-1.04-.42-.9.68c-.43.32-.84.56-1.25.73l-1.06.43-.16 1.13-.2 1.35h-1.4l-.19-1.35-.16-1.13-1.06-.43c-.43-.18-.83-.41-1.23-.71l-.91-.7-1.06.43-1.27.51-.7-1.21 1.08-.84.89-.7-.14-1.13c-.03-.31-.05-.54-.05-.74s.02-.43.05-.73l.14-1.13-.89-.7-1.08-.84.7-1.21 1.27.51 1.04.42.9-.68c.43-.32.84-.56 1.25-.73l1.06-.43.16-1.13.2-1.35h1.39l.19 1.35.16 1.13 1.06.43c.43.18.83.41 1.23.71l.91.7 1.06-.43 1.27-.51.7 1.21-1.07.85-.89.7zM12 8c-2.21 0-4 1.79-4 4s1.79 4 4 4 4-1.79 4-4-1.79-4-4-4m0 6c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2"
		}), 'SettingsOutlined');
		return SettingsOutlined;
	}

	var SettingsOutlinedExports = /*@__PURE__*/ requireSettingsOutlined();
	var SettingsOutlinedIcon = /*@__PURE__*/getDefaultExportFromCjs(SettingsOutlinedExports);

	var GroupOutlined = {};

	var hasRequiredGroupOutlined;

	function requireGroupOutlined () {
		if (hasRequiredGroupOutlined) return GroupOutlined;
		hasRequiredGroupOutlined = 1;

		var _interopRequireDefault = requireInteropRequireDefault();
		Object.defineProperty(GroupOutlined, "__esModule", {
		  value: true
		});
		GroupOutlined.default = void 0;
		var _createSvgIcon = _interopRequireDefault(/*@__PURE__*/ requireCreateSvgIcon());
		var _jsxRuntime = requireJsxRuntime();
		GroupOutlined.default = (0, _createSvgIcon.default)(/*#__PURE__*/(0, _jsxRuntime.jsx)("path", {
		  d: "M9 13.75c-2.34 0-7 1.17-7 3.5V19h14v-1.75c0-2.33-4.66-3.5-7-3.5M4.34 17c.84-.58 2.87-1.25 4.66-1.25s3.82.67 4.66 1.25zM9 12c1.93 0 3.5-1.57 3.5-3.5S10.93 5 9 5 5.5 6.57 5.5 8.5 7.07 12 9 12m0-5c.83 0 1.5.67 1.5 1.5S9.83 10 9 10s-1.5-.67-1.5-1.5S8.17 7 9 7m7.04 6.81c1.16.84 1.96 1.96 1.96 3.44V19h4v-1.75c0-2.02-3.5-3.17-5.96-3.44M15 12c1.93 0 3.5-1.57 3.5-3.5S16.93 5 15 5c-.54 0-1.04.13-1.5.35.63.89 1 1.98 1 3.15s-.37 2.26-1 3.15c.46.22.96.35 1.5.35"
		}), 'GroupOutlined');
		return GroupOutlined;
	}

	var GroupOutlinedExports = /*@__PURE__*/ requireGroupOutlined();
	var GroupOutlinedIcon = /*@__PURE__*/getDefaultExportFromCjs(GroupOutlinedExports);

	var NotificationsNoneOutlined = {};

	var hasRequiredNotificationsNoneOutlined;

	function requireNotificationsNoneOutlined () {
		if (hasRequiredNotificationsNoneOutlined) return NotificationsNoneOutlined;
		hasRequiredNotificationsNoneOutlined = 1;

		var _interopRequireDefault = requireInteropRequireDefault();
		Object.defineProperty(NotificationsNoneOutlined, "__esModule", {
		  value: true
		});
		NotificationsNoneOutlined.default = void 0;
		var _createSvgIcon = _interopRequireDefault(/*@__PURE__*/ requireCreateSvgIcon());
		var _jsxRuntime = requireJsxRuntime();
		NotificationsNoneOutlined.default = (0, _createSvgIcon.default)(/*#__PURE__*/(0, _jsxRuntime.jsx)("path", {
		  d: "M12 22c1.1 0 2-.9 2-2h-4c0 1.1.9 2 2 2m6-6v-5c0-3.07-1.63-5.64-4.5-6.32V4c0-.83-.67-1.5-1.5-1.5s-1.5.67-1.5 1.5v.68C7.64 5.36 6 7.92 6 11v5l-2 2v1h16v-1zm-2 1H8v-6c0-2.48 1.51-4.5 4-4.5s4 2.02 4 4.5z"
		}), 'NotificationsNoneOutlined');
		return NotificationsNoneOutlined;
	}

	var NotificationsNoneOutlinedExports = /*@__PURE__*/ requireNotificationsNoneOutlined();
	var NotificationsNoneOutlinedIcon = /*@__PURE__*/getDefaultExportFromCjs(NotificationsNoneOutlinedExports);

	var SecurityOutlined = {};

	var hasRequiredSecurityOutlined;

	function requireSecurityOutlined () {
		if (hasRequiredSecurityOutlined) return SecurityOutlined;
		hasRequiredSecurityOutlined = 1;

		var _interopRequireDefault = requireInteropRequireDefault();
		Object.defineProperty(SecurityOutlined, "__esModule", {
		  value: true
		});
		SecurityOutlined.default = void 0;
		var _createSvgIcon = _interopRequireDefault(/*@__PURE__*/ requireCreateSvgIcon());
		var _jsxRuntime = requireJsxRuntime();
		SecurityOutlined.default = (0, _createSvgIcon.default)(/*#__PURE__*/(0, _jsxRuntime.jsx)("path", {
		  d: "M12 1 3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11z"
		}), 'SecurityOutlined');
		return SecurityOutlined;
	}

	var SecurityOutlinedExports = /*@__PURE__*/ requireSecurityOutlined();
	var SecurityOutlinedIcon = /*@__PURE__*/getDefaultExportFromCjs(SecurityOutlinedExports);

	function _setPrototypeOf(t, e) {
	  return _setPrototypeOf = Object.setPrototypeOf ? Object.setPrototypeOf.bind() : function (t, e) {
	    return t.__proto__ = e, t;
	  }, _setPrototypeOf(t, e);
	}

	function _inheritsLoose(t, o) {
	  t.prototype = Object.create(o.prototype), t.prototype.constructor = t, _setPrototypeOf(t, o);
	}

	var reactDomExports = requireReactDom();
	var ReactDOM = /*@__PURE__*/getDefaultExportFromCjs(reactDomExports);

	var config = {
	  disabled: false
	};

	var TransitionGroupContext = /*#__PURE__*/React.createContext(null);

	var forceReflow = function forceReflow(node) {
	  return node.scrollTop;
	};

	var UNMOUNTED = 'unmounted';
	var EXITED = 'exited';
	var ENTERING = 'entering';
	var ENTERED = 'entered';
	var EXITING = 'exiting';
	/**
	 * The Transition component lets you describe a transition from one component
	 * state to another _over time_ with a simple declarative API. Most commonly
	 * it's used to animate the mounting and unmounting of a component, but can also
	 * be used to describe in-place transition states as well.
	 *
	 * ---
	 *
	 * **Note**: `Transition` is a platform-agnostic base component. If you're using
	 * transitions in CSS, you'll probably want to use
	 * [`CSSTransition`](https://reactcommunity.org/react-transition-group/css-transition)
	 * instead. It inherits all the features of `Transition`, but contains
	 * additional features necessary to play nice with CSS transitions (hence the
	 * name of the component).
	 *
	 * ---
	 *
	 * By default the `Transition` component does not alter the behavior of the
	 * component it renders, it only tracks "enter" and "exit" states for the
	 * components. It's up to you to give meaning and effect to those states. For
	 * example we can add styles to a component when it enters or exits:
	 *
	 * ```jsx
	 * import { Transition } from 'react-transition-group';
	 *
	 * const duration = 300;
	 *
	 * const defaultStyle = {
	 *   transition: `opacity ${duration}ms ease-in-out`,
	 *   opacity: 0,
	 * }
	 *
	 * const transitionStyles = {
	 *   entering: { opacity: 1 },
	 *   entered:  { opacity: 1 },
	 *   exiting:  { opacity: 0 },
	 *   exited:  { opacity: 0 },
	 * };
	 *
	 * const Fade = ({ in: inProp }) => (
	 *   <Transition in={inProp} timeout={duration}>
	 *     {state => (
	 *       <div style={{
	 *         ...defaultStyle,
	 *         ...transitionStyles[state]
	 *       }}>
	 *         I'm a fade Transition!
	 *       </div>
	 *     )}
	 *   </Transition>
	 * );
	 * ```
	 *
	 * There are 4 main states a Transition can be in:
	 *  - `'entering'`
	 *  - `'entered'`
	 *  - `'exiting'`
	 *  - `'exited'`
	 *
	 * Transition state is toggled via the `in` prop. When `true` the component
	 * begins the "Enter" stage. During this stage, the component will shift from
	 * its current transition state, to `'entering'` for the duration of the
	 * transition and then to the `'entered'` stage once it's complete. Let's take
	 * the following example (we'll use the
	 * [useState](https://reactjs.org/docs/hooks-reference.html#usestate) hook):
	 *
	 * ```jsx
	 * function App() {
	 *   const [inProp, setInProp] = useState(false);
	 *   return (
	 *     <div>
	 *       <Transition in={inProp} timeout={500}>
	 *         {state => (
	 *           // ...
	 *         )}
	 *       </Transition>
	 *       <button onClick={() => setInProp(true)}>
	 *         Click to Enter
	 *       </button>
	 *     </div>
	 *   );
	 * }
	 * ```
	 *
	 * When the button is clicked the component will shift to the `'entering'` state
	 * and stay there for 500ms (the value of `timeout`) before it finally switches
	 * to `'entered'`.
	 *
	 * When `in` is `false` the same thing happens except the state moves from
	 * `'exiting'` to `'exited'`.
	 */

	var Transition = /*#__PURE__*/function (_React$Component) {
	  _inheritsLoose(Transition, _React$Component);
	  function Transition(props, context) {
	    var _this;
	    _this = _React$Component.call(this, props, context) || this;
	    var parentGroup = context; // In the context of a TransitionGroup all enters are really appears

	    var appear = parentGroup && !parentGroup.isMounting ? props.enter : props.appear;
	    var initialStatus;
	    _this.appearStatus = null;
	    if (props.in) {
	      if (appear) {
	        initialStatus = EXITED;
	        _this.appearStatus = ENTERING;
	      } else {
	        initialStatus = ENTERED;
	      }
	    } else {
	      if (props.unmountOnExit || props.mountOnEnter) {
	        initialStatus = UNMOUNTED;
	      } else {
	        initialStatus = EXITED;
	      }
	    }
	    _this.state = {
	      status: initialStatus
	    };
	    _this.nextCallback = null;
	    return _this;
	  }
	  Transition.getDerivedStateFromProps = function getDerivedStateFromProps(_ref, prevState) {
	    var nextIn = _ref.in;
	    if (nextIn && prevState.status === UNMOUNTED) {
	      return {
	        status: EXITED
	      };
	    }
	    return null;
	  } // getSnapshotBeforeUpdate(prevProps) {
	  //   let nextStatus = null
	  //   if (prevProps !== this.props) {
	  //     const { status } = this.state
	  //     if (this.props.in) {
	  //       if (status !== ENTERING && status !== ENTERED) {
	  //         nextStatus = ENTERING
	  //       }
	  //     } else {
	  //       if (status === ENTERING || status === ENTERED) {
	  //         nextStatus = EXITING
	  //       }
	  //     }
	  //   }
	  //   return { nextStatus }
	  // }
	;
	  var _proto = Transition.prototype;
	  _proto.componentDidMount = function componentDidMount() {
	    this.updateStatus(true, this.appearStatus);
	  };
	  _proto.componentDidUpdate = function componentDidUpdate(prevProps) {
	    var nextStatus = null;
	    if (prevProps !== this.props) {
	      var status = this.state.status;
	      if (this.props.in) {
	        if (status !== ENTERING && status !== ENTERED) {
	          nextStatus = ENTERING;
	        }
	      } else {
	        if (status === ENTERING || status === ENTERED) {
	          nextStatus = EXITING;
	        }
	      }
	    }
	    this.updateStatus(false, nextStatus);
	  };
	  _proto.componentWillUnmount = function componentWillUnmount() {
	    this.cancelNextCallback();
	  };
	  _proto.getTimeouts = function getTimeouts() {
	    var timeout = this.props.timeout;
	    var exit, enter, appear;
	    exit = enter = appear = timeout;
	    if (timeout != null && typeof timeout !== 'number') {
	      exit = timeout.exit;
	      enter = timeout.enter; // TODO: remove fallback for next major

	      appear = timeout.appear !== undefined ? timeout.appear : enter;
	    }
	    return {
	      exit: exit,
	      enter: enter,
	      appear: appear
	    };
	  };
	  _proto.updateStatus = function updateStatus(mounting, nextStatus) {
	    if (mounting === void 0) {
	      mounting = false;
	    }
	    if (nextStatus !== null) {
	      // nextStatus will always be ENTERING or EXITING.
	      this.cancelNextCallback();
	      if (nextStatus === ENTERING) {
	        if (this.props.unmountOnExit || this.props.mountOnEnter) {
	          var node = this.props.nodeRef ? this.props.nodeRef.current : ReactDOM.findDOMNode(this); // https://github.com/reactjs/react-transition-group/pull/749
	          // With unmountOnExit or mountOnEnter, the enter animation should happen at the transition between `exited` and `entering`.
	          // To make the animation happen,  we have to separate each rendering and avoid being processed as batched.

	          if (node) forceReflow(node);
	        }
	        this.performEnter(mounting);
	      } else {
	        this.performExit();
	      }
	    } else if (this.props.unmountOnExit && this.state.status === EXITED) {
	      this.setState({
	        status: UNMOUNTED
	      });
	    }
	  };
	  _proto.performEnter = function performEnter(mounting) {
	    var _this2 = this;
	    var enter = this.props.enter;
	    var appearing = this.context ? this.context.isMounting : mounting;
	    var _ref2 = this.props.nodeRef ? [appearing] : [ReactDOM.findDOMNode(this), appearing],
	      maybeNode = _ref2[0],
	      maybeAppearing = _ref2[1];
	    var timeouts = this.getTimeouts();
	    var enterTimeout = appearing ? timeouts.appear : timeouts.enter; // no enter animation skip right to ENTERED
	    // if we are mounting and running this it means appear _must_ be set

	    if (!mounting && !enter || config.disabled) {
	      this.safeSetState({
	        status: ENTERED
	      }, function () {
	        _this2.props.onEntered(maybeNode);
	      });
	      return;
	    }
	    this.props.onEnter(maybeNode, maybeAppearing);
	    this.safeSetState({
	      status: ENTERING
	    }, function () {
	      _this2.props.onEntering(maybeNode, maybeAppearing);
	      _this2.onTransitionEnd(enterTimeout, function () {
	        _this2.safeSetState({
	          status: ENTERED
	        }, function () {
	          _this2.props.onEntered(maybeNode, maybeAppearing);
	        });
	      });
	    });
	  };
	  _proto.performExit = function performExit() {
	    var _this3 = this;
	    var exit = this.props.exit;
	    var timeouts = this.getTimeouts();
	    var maybeNode = this.props.nodeRef ? undefined : ReactDOM.findDOMNode(this); // no exit animation skip right to EXITED

	    if (!exit || config.disabled) {
	      this.safeSetState({
	        status: EXITED
	      }, function () {
	        _this3.props.onExited(maybeNode);
	      });
	      return;
	    }
	    this.props.onExit(maybeNode);
	    this.safeSetState({
	      status: EXITING
	    }, function () {
	      _this3.props.onExiting(maybeNode);
	      _this3.onTransitionEnd(timeouts.exit, function () {
	        _this3.safeSetState({
	          status: EXITED
	        }, function () {
	          _this3.props.onExited(maybeNode);
	        });
	      });
	    });
	  };
	  _proto.cancelNextCallback = function cancelNextCallback() {
	    if (this.nextCallback !== null) {
	      this.nextCallback.cancel();
	      this.nextCallback = null;
	    }
	  };
	  _proto.safeSetState = function safeSetState(nextState, callback) {
	    // This shouldn't be necessary, but there are weird race conditions with
	    // setState callbacks and unmounting in testing, so always make sure that
	    // we can cancel any pending setState callbacks after we unmount.
	    callback = this.setNextCallback(callback);
	    this.setState(nextState, callback);
	  };
	  _proto.setNextCallback = function setNextCallback(callback) {
	    var _this4 = this;
	    var active = true;
	    this.nextCallback = function (event) {
	      if (active) {
	        active = false;
	        _this4.nextCallback = null;
	        callback(event);
	      }
	    };
	    this.nextCallback.cancel = function () {
	      active = false;
	    };
	    return this.nextCallback;
	  };
	  _proto.onTransitionEnd = function onTransitionEnd(timeout, handler) {
	    this.setNextCallback(handler);
	    var node = this.props.nodeRef ? this.props.nodeRef.current : ReactDOM.findDOMNode(this);
	    var doesNotHaveTimeoutOrListener = timeout == null && !this.props.addEndListener;
	    if (!node || doesNotHaveTimeoutOrListener) {
	      setTimeout(this.nextCallback, 0);
	      return;
	    }
	    if (this.props.addEndListener) {
	      var _ref3 = this.props.nodeRef ? [this.nextCallback] : [node, this.nextCallback],
	        maybeNode = _ref3[0],
	        maybeNextCallback = _ref3[1];
	      this.props.addEndListener(maybeNode, maybeNextCallback);
	    }
	    if (timeout != null) {
	      setTimeout(this.nextCallback, timeout);
	    }
	  };
	  _proto.render = function render() {
	    var status = this.state.status;
	    if (status === UNMOUNTED) {
	      return null;
	    }
	    var _this$props = this.props,
	      children = _this$props.children;
	      _this$props.in;
	      _this$props.mountOnEnter;
	      _this$props.unmountOnExit;
	      _this$props.appear;
	      _this$props.enter;
	      _this$props.exit;
	      _this$props.timeout;
	      _this$props.addEndListener;
	      _this$props.onEnter;
	      _this$props.onEntering;
	      _this$props.onEntered;
	      _this$props.onExit;
	      _this$props.onExiting;
	      _this$props.onExited;
	      _this$props.nodeRef;
	      var childProps = _objectWithoutPropertiesLoose(_this$props, ["children", "in", "mountOnEnter", "unmountOnExit", "appear", "enter", "exit", "timeout", "addEndListener", "onEnter", "onEntering", "onEntered", "onExit", "onExiting", "onExited", "nodeRef"]);
	    return (/*#__PURE__*/
	      // allows for nested Transitions
	      React.createElement(TransitionGroupContext.Provider, {
	        value: null
	      }, typeof children === 'function' ? children(status, childProps) : /*#__PURE__*/React.cloneElement(React.Children.only(children), childProps))
	    );
	  };
	  return Transition;
	}(React.Component);
	Transition.contextType = TransitionGroupContext;
	Transition.propTypes = {}; // Name the function so it is clearer in the documentation

	function noop() {}
	Transition.defaultProps = {
	  in: false,
	  mountOnEnter: false,
	  unmountOnExit: false,
	  appear: false,
	  enter: true,
	  exit: true,
	  onEnter: noop,
	  onEntering: noop,
	  onEntered: noop,
	  onExit: noop,
	  onExiting: noop,
	  onExited: noop
	};
	Transition.UNMOUNTED = UNMOUNTED;
	Transition.EXITED = EXITED;
	Transition.ENTERING = ENTERING;
	Transition.ENTERED = ENTERED;
	Transition.EXITING = EXITING;
	var Transition$1 = Transition;

	function _assertThisInitialized(e) {
	  if (void 0 === e) throw new ReferenceError("this hasn't been initialised - super() hasn't been called");
	  return e;
	}

	/**
	 * Given `this.props.children`, return an object mapping key to child.
	 *
	 * @param {*} children `this.props.children`
	 * @return {object} Mapping of key to child
	 */

	function getChildMapping(children, mapFn) {
	  var mapper = function mapper(child) {
	    return mapFn && /*#__PURE__*/reactExports.isValidElement(child) ? mapFn(child) : child;
	  };
	  var result = Object.create(null);
	  if (children) reactExports.Children.map(children, function (c) {
	    return c;
	  }).forEach(function (child) {
	    // run the map function here instead so that the key is the computed one
	    result[child.key] = mapper(child);
	  });
	  return result;
	}
	/**
	 * When you're adding or removing children some may be added or removed in the
	 * same render pass. We want to show *both* since we want to simultaneously
	 * animate elements in and out. This function takes a previous set of keys
	 * and a new set of keys and merges them with its best guess of the correct
	 * ordering. In the future we may expose some of the utilities in
	 * ReactMultiChild to make this easy, but for now React itself does not
	 * directly have this concept of the union of prevChildren and nextChildren
	 * so we implement it here.
	 *
	 * @param {object} prev prev children as returned from
	 * `ReactTransitionChildMapping.getChildMapping()`.
	 * @param {object} next next children as returned from
	 * `ReactTransitionChildMapping.getChildMapping()`.
	 * @return {object} a key set that contains all keys in `prev` and all keys
	 * in `next` in a reasonable order.
	 */

	function mergeChildMappings(prev, next) {
	  prev = prev || {};
	  next = next || {};
	  function getValueForKey(key) {
	    return key in next ? next[key] : prev[key];
	  } // For each key of `next`, the list of keys to insert before that key in
	  // the combined list

	  var nextKeysPending = Object.create(null);
	  var pendingKeys = [];
	  for (var prevKey in prev) {
	    if (prevKey in next) {
	      if (pendingKeys.length) {
	        nextKeysPending[prevKey] = pendingKeys;
	        pendingKeys = [];
	      }
	    } else {
	      pendingKeys.push(prevKey);
	    }
	  }
	  var i;
	  var childMapping = {};
	  for (var nextKey in next) {
	    if (nextKeysPending[nextKey]) {
	      for (i = 0; i < nextKeysPending[nextKey].length; i++) {
	        var pendingNextKey = nextKeysPending[nextKey][i];
	        childMapping[nextKeysPending[nextKey][i]] = getValueForKey(pendingNextKey);
	      }
	    }
	    childMapping[nextKey] = getValueForKey(nextKey);
	  } // Finally, add the keys which didn't appear before any key in `next`

	  for (i = 0; i < pendingKeys.length; i++) {
	    childMapping[pendingKeys[i]] = getValueForKey(pendingKeys[i]);
	  }
	  return childMapping;
	}
	function getProp(child, prop, props) {
	  return props[prop] != null ? props[prop] : child.props[prop];
	}
	function getInitialChildMapping(props, onExited) {
	  return getChildMapping(props.children, function (child) {
	    return /*#__PURE__*/reactExports.cloneElement(child, {
	      onExited: onExited.bind(null, child),
	      in: true,
	      appear: getProp(child, 'appear', props),
	      enter: getProp(child, 'enter', props),
	      exit: getProp(child, 'exit', props)
	    });
	  });
	}
	function getNextChildMapping(nextProps, prevChildMapping, onExited) {
	  var nextChildMapping = getChildMapping(nextProps.children);
	  var children = mergeChildMappings(prevChildMapping, nextChildMapping);
	  Object.keys(children).forEach(function (key) {
	    var child = children[key];
	    if (! /*#__PURE__*/reactExports.isValidElement(child)) return;
	    var hasPrev = key in prevChildMapping;
	    var hasNext = key in nextChildMapping;
	    var prevChild = prevChildMapping[key];
	    var isLeaving = /*#__PURE__*/reactExports.isValidElement(prevChild) && !prevChild.props.in; // item is new (entering)

	    if (hasNext && (!hasPrev || isLeaving)) {
	      // console.log('entering', key)
	      children[key] = /*#__PURE__*/reactExports.cloneElement(child, {
	        onExited: onExited.bind(null, child),
	        in: true,
	        exit: getProp(child, 'exit', nextProps),
	        enter: getProp(child, 'enter', nextProps)
	      });
	    } else if (!hasNext && hasPrev && !isLeaving) {
	      // item is old (exiting)
	      // console.log('leaving', key)
	      children[key] = /*#__PURE__*/reactExports.cloneElement(child, {
	        in: false
	      });
	    } else if (hasNext && hasPrev && /*#__PURE__*/reactExports.isValidElement(prevChild)) {
	      // item hasn't changed transition states
	      // copy over the last transition props;
	      // console.log('unchanged', key)
	      children[key] = /*#__PURE__*/reactExports.cloneElement(child, {
	        onExited: onExited.bind(null, child),
	        in: prevChild.props.in,
	        exit: getProp(child, 'exit', nextProps),
	        enter: getProp(child, 'enter', nextProps)
	      });
	    }
	  });
	  return children;
	}

	var values = Object.values || function (obj) {
	  return Object.keys(obj).map(function (k) {
	    return obj[k];
	  });
	};
	var defaultProps = {
	  component: 'div',
	  childFactory: function childFactory(child) {
	    return child;
	  }
	};
	/**
	 * The `<TransitionGroup>` component manages a set of transition components
	 * (`<Transition>` and `<CSSTransition>`) in a list. Like with the transition
	 * components, `<TransitionGroup>` is a state machine for managing the mounting
	 * and unmounting of components over time.
	 *
	 * Consider the example below. As items are removed or added to the TodoList the
	 * `in` prop is toggled automatically by the `<TransitionGroup>`.
	 *
	 * Note that `<TransitionGroup>`  does not define any animation behavior!
	 * Exactly _how_ a list item animates is up to the individual transition
	 * component. This means you can mix and match animations across different list
	 * items.
	 */

	var TransitionGroup = /*#__PURE__*/function (_React$Component) {
	  _inheritsLoose(TransitionGroup, _React$Component);
	  function TransitionGroup(props, context) {
	    var _this;
	    _this = _React$Component.call(this, props, context) || this;
	    var handleExited = _this.handleExited.bind(_assertThisInitialized(_this)); // Initial children should all be entering, dependent on appear

	    _this.state = {
	      contextValue: {
	        isMounting: true
	      },
	      handleExited: handleExited,
	      firstRender: true
	    };
	    return _this;
	  }
	  var _proto = TransitionGroup.prototype;
	  _proto.componentDidMount = function componentDidMount() {
	    this.mounted = true;
	    this.setState({
	      contextValue: {
	        isMounting: false
	      }
	    });
	  };
	  _proto.componentWillUnmount = function componentWillUnmount() {
	    this.mounted = false;
	  };
	  TransitionGroup.getDerivedStateFromProps = function getDerivedStateFromProps(nextProps, _ref) {
	    var prevChildMapping = _ref.children,
	      handleExited = _ref.handleExited,
	      firstRender = _ref.firstRender;
	    return {
	      children: firstRender ? getInitialChildMapping(nextProps, handleExited) : getNextChildMapping(nextProps, prevChildMapping, handleExited),
	      firstRender: false
	    };
	  } // node is `undefined` when user provided `nodeRef` prop
	;
	  _proto.handleExited = function handleExited(child, node) {
	    var currentChildMapping = getChildMapping(this.props.children);
	    if (child.key in currentChildMapping) return;
	    if (child.props.onExited) {
	      child.props.onExited(node);
	    }
	    if (this.mounted) {
	      this.setState(function (state) {
	        var children = _extends$1({}, state.children);
	        delete children[child.key];
	        return {
	          children: children
	        };
	      });
	    }
	  };
	  _proto.render = function render() {
	    var _this$props = this.props,
	      Component = _this$props.component,
	      childFactory = _this$props.childFactory,
	      props = _objectWithoutPropertiesLoose(_this$props, ["component", "childFactory"]);
	    var contextValue = this.state.contextValue;
	    var children = values(this.state.children).map(childFactory);
	    delete props.appear;
	    delete props.enter;
	    delete props.exit;
	    if (Component === null) {
	      return /*#__PURE__*/React.createElement(TransitionGroupContext.Provider, {
	        value: contextValue
	      }, children);
	    }
	    return /*#__PURE__*/React.createElement(TransitionGroupContext.Provider, {
	      value: contextValue
	    }, /*#__PURE__*/React.createElement(Component, props, children));
	  };
	  return TransitionGroup;
	}(React.Component);
	TransitionGroup.propTypes = {};
	TransitionGroup.defaultProps = defaultProps;
	var TransitionGroup$1 = TransitionGroup;

	const reflow = node => node.scrollTop;
	function getTransitionProps(props, options) {
	  var _style$transitionDura, _style$transitionTimi;
	  const {
	    timeout,
	    easing,
	    style = {}
	  } = props;
	  return {
	    duration: (_style$transitionDura = style.transitionDuration) != null ? _style$transitionDura : typeof timeout === 'number' ? timeout : timeout[options.mode] || 0,
	    easing: (_style$transitionTimi = style.transitionTimingFunction) != null ? _style$transitionTimi : typeof easing === 'object' ? easing[options.mode] : easing,
	    delay: style.transitionDelay
	  };
	}

	function getPaperUtilityClass(slot) {
	  return generateUtilityClass('MuiPaper', slot);
	}
	generateUtilityClasses('MuiPaper', ['root', 'rounded', 'outlined', 'elevation', 'elevation0', 'elevation1', 'elevation2', 'elevation3', 'elevation4', 'elevation5', 'elevation6', 'elevation7', 'elevation8', 'elevation9', 'elevation10', 'elevation11', 'elevation12', 'elevation13', 'elevation14', 'elevation15', 'elevation16', 'elevation17', 'elevation18', 'elevation19', 'elevation20', 'elevation21', 'elevation22', 'elevation23', 'elevation24']);

	const _excluded$m = ["className", "component", "elevation", "square", "variant"];
	const useUtilityClasses$g = ownerState => {
	  const {
	    square,
	    elevation,
	    variant,
	    classes
	  } = ownerState;
	  const slots = {
	    root: ['root', variant, !square && 'rounded', variant === 'elevation' && `elevation${elevation}`]
	  };
	  return composeClasses(slots, getPaperUtilityClass, classes);
	};
	const PaperRoot = styled$1('div', {
	  name: 'MuiPaper',
	  slot: 'Root',
	  overridesResolver: (props, styles) => {
	    const {
	      ownerState
	    } = props;
	    return [styles.root, styles[ownerState.variant], !ownerState.square && styles.rounded, ownerState.variant === 'elevation' && styles[`elevation${ownerState.elevation}`]];
	  }
	})(({
	  theme,
	  ownerState
	}) => {
	  var _theme$vars$overlays;
	  return _extends$1({
	    backgroundColor: (theme.vars || theme).palette.background.paper,
	    color: (theme.vars || theme).palette.text.primary,
	    transition: theme.transitions.create('box-shadow')
	  }, !ownerState.square && {
	    borderRadius: theme.shape.borderRadius
	  }, ownerState.variant === 'outlined' && {
	    border: `1px solid ${(theme.vars || theme).palette.divider}`
	  }, ownerState.variant === 'elevation' && _extends$1({
	    boxShadow: (theme.vars || theme).shadows[ownerState.elevation]
	  }, !theme.vars && theme.palette.mode === 'dark' && {
	    backgroundImage: `linear-gradient(${colorManipulatorExports.alpha('#fff', getOverlayAlpha$1(ownerState.elevation))}, ${colorManipulatorExports.alpha('#fff', getOverlayAlpha$1(ownerState.elevation))})`
	  }, theme.vars && {
	    backgroundImage: (_theme$vars$overlays = theme.vars.overlays) == null ? void 0 : _theme$vars$overlays[ownerState.elevation]
	  }));
	});
	const Paper = /*#__PURE__*/reactExports.forwardRef(function Paper(inProps, ref) {
	  const props = useThemeProps({
	    props: inProps,
	    name: 'MuiPaper'
	  });
	  const {
	      className,
	      component = 'div',
	      elevation = 1,
	      square = false,
	      variant = 'elevation'
	    } = props,
	    other = _objectWithoutPropertiesLoose(props, _excluded$m);
	  const ownerState = _extends$1({}, props, {
	    component,
	    elevation,
	    square,
	    variant
	  });
	  const classes = useUtilityClasses$g(ownerState);
	  return /*#__PURE__*/jsxRuntimeExports.jsx(PaperRoot, _extends$1({
	    as: component,
	    ownerState: ownerState,
	    className: clsx(classes.root, className),
	    ref: ref
	  }, other));
	});
	var Paper$1 = Paper;

	/**
	 * Determines if a given element is a DOM element name (i.e. not a React component).
	 */
	function isHostComponent(element) {
	  return typeof element === 'string';
	}

	/**
	 * Type of the ownerState based on the type of an element it applies to.
	 * This resolves to the provided OwnerState for React components and `undefined` for host components.
	 * Falls back to `OwnerState | undefined` when the exact type can't be determined in development time.
	 */

	/**
	 * Appends the ownerState object to the props, merging with the existing one if necessary.
	 *
	 * @param elementType Type of the element that owns the `existingProps`. If the element is a DOM node or undefined, `ownerState` is not applied.
	 * @param otherProps Props of the element.
	 * @param ownerState
	 */
	function appendOwnerState(elementType, otherProps, ownerState) {
	  if (elementType === undefined || isHostComponent(elementType)) {
	    return otherProps;
	  }
	  return _extends$1({}, otherProps, {
	    ownerState: _extends$1({}, otherProps.ownerState, ownerState)
	  });
	}

	/**
	 * Extracts event handlers from a given object.
	 * A prop is considered an event handler if it is a function and its name starts with `on`.
	 *
	 * @param object An object to extract event handlers from.
	 * @param excludeKeys An array of keys to exclude from the returned object.
	 */
	function extractEventHandlers(object, excludeKeys = []) {
	  if (object === undefined) {
	    return {};
	  }
	  const result = {};
	  Object.keys(object).filter(prop => prop.match(/^on[A-Z]/) && typeof object[prop] === 'function' && !excludeKeys.includes(prop)).forEach(prop => {
	    result[prop] = object[prop];
	  });
	  return result;
	}

	/**
	 * If `componentProps` is a function, calls it with the provided `ownerState`.
	 * Otherwise, just returns `componentProps`.
	 */
	function resolveComponentProps(componentProps, ownerState, slotState) {
	  if (typeof componentProps === 'function') {
	    return componentProps(ownerState, slotState);
	  }
	  return componentProps;
	}

	/**
	 * Removes event handlers from the given object.
	 * A field is considered an event handler if it is a function with a name beginning with `on`.
	 *
	 * @param object Object to remove event handlers from.
	 * @returns Object with event handlers removed.
	 */
	function omitEventHandlers(object) {
	  if (object === undefined) {
	    return {};
	  }
	  const result = {};
	  Object.keys(object).filter(prop => !(prop.match(/^on[A-Z]/) && typeof object[prop] === 'function')).forEach(prop => {
	    result[prop] = object[prop];
	  });
	  return result;
	}

	/**
	 * Merges the slot component internal props (usually coming from a hook)
	 * with the externally provided ones.
	 *
	 * The merge order is (the latter overrides the former):
	 * 1. The internal props (specified as a getter function to work with get*Props hook result)
	 * 2. Additional props (specified internally on a Base UI component)
	 * 3. External props specified on the owner component. These should only be used on a root slot.
	 * 4. External props specified in the `slotProps.*` prop.
	 * 5. The `className` prop - combined from all the above.
	 * @param parameters
	 * @returns
	 */
	function mergeSlotProps(parameters) {
	  const {
	    getSlotProps,
	    additionalProps,
	    externalSlotProps,
	    externalForwardedProps,
	    className
	  } = parameters;
	  if (!getSlotProps) {
	    // The simpler case - getSlotProps is not defined, so no internal event handlers are defined,
	    // so we can simply merge all the props without having to worry about extracting event handlers.
	    const joinedClasses = clsx(additionalProps == null ? void 0 : additionalProps.className, className, externalForwardedProps == null ? void 0 : externalForwardedProps.className, externalSlotProps == null ? void 0 : externalSlotProps.className);
	    const mergedStyle = _extends$1({}, additionalProps == null ? void 0 : additionalProps.style, externalForwardedProps == null ? void 0 : externalForwardedProps.style, externalSlotProps == null ? void 0 : externalSlotProps.style);
	    const props = _extends$1({}, additionalProps, externalForwardedProps, externalSlotProps);
	    if (joinedClasses.length > 0) {
	      props.className = joinedClasses;
	    }
	    if (Object.keys(mergedStyle).length > 0) {
	      props.style = mergedStyle;
	    }
	    return {
	      props,
	      internalRef: undefined
	    };
	  }

	  // In this case, getSlotProps is responsible for calling the external event handlers.
	  // We don't need to include them in the merged props because of this.

	  const eventHandlers = extractEventHandlers(_extends$1({}, externalForwardedProps, externalSlotProps));
	  const componentsPropsWithoutEventHandlers = omitEventHandlers(externalSlotProps);
	  const otherPropsWithoutEventHandlers = omitEventHandlers(externalForwardedProps);
	  const internalSlotProps = getSlotProps(eventHandlers);

	  // The order of classes is important here.
	  // Emotion (that we use in libraries consuming Base UI) depends on this order
	  // to properly override style. It requires the most important classes to be last
	  // (see https://github.com/mui/material-ui/pull/33205) for the related discussion.
	  const joinedClasses = clsx(internalSlotProps == null ? void 0 : internalSlotProps.className, additionalProps == null ? void 0 : additionalProps.className, className, externalForwardedProps == null ? void 0 : externalForwardedProps.className, externalSlotProps == null ? void 0 : externalSlotProps.className);
	  const mergedStyle = _extends$1({}, internalSlotProps == null ? void 0 : internalSlotProps.style, additionalProps == null ? void 0 : additionalProps.style, externalForwardedProps == null ? void 0 : externalForwardedProps.style, externalSlotProps == null ? void 0 : externalSlotProps.style);
	  const props = _extends$1({}, internalSlotProps, additionalProps, otherPropsWithoutEventHandlers, componentsPropsWithoutEventHandlers);
	  if (joinedClasses.length > 0) {
	    props.className = joinedClasses;
	  }
	  if (Object.keys(mergedStyle).length > 0) {
	    props.style = mergedStyle;
	  }
	  return {
	    props,
	    internalRef: internalSlotProps.ref
	  };
	}

	const _excluded$l = ["elementType", "externalSlotProps", "ownerState", "skipResolvingSlotProps"];
	/**
	 * @ignore - do not document.
	 * Builds the props to be passed into the slot of an unstyled component.
	 * It merges the internal props of the component with the ones supplied by the user, allowing to customize the behavior.
	 * If the slot component is not a host component, it also merges in the `ownerState`.
	 *
	 * @param parameters.getSlotProps - A function that returns the props to be passed to the slot component.
	 */
	function useSlotProps(parameters) {
	  var _parameters$additiona;
	  const {
	      elementType,
	      externalSlotProps,
	      ownerState,
	      skipResolvingSlotProps = false
	    } = parameters,
	    rest = _objectWithoutPropertiesLoose(parameters, _excluded$l);
	  const resolvedComponentsProps = skipResolvingSlotProps ? {} : resolveComponentProps(externalSlotProps, ownerState);
	  const {
	    props: mergedProps,
	    internalRef
	  } = mergeSlotProps(_extends$1({}, rest, {
	    externalSlotProps: resolvedComponentsProps
	  }));
	  const ref = useForkRef(internalRef, resolvedComponentsProps == null ? void 0 : resolvedComponentsProps.ref, (_parameters$additiona = parameters.additionalProps) == null ? void 0 : _parameters$additiona.ref);
	  const props = appendOwnerState(elementType, _extends$1({}, mergedProps, {
	    ref
	  }), ownerState);
	  return props;
	}

	function Ripple(props) {
	  const {
	    className,
	    classes,
	    pulsate = false,
	    rippleX,
	    rippleY,
	    rippleSize,
	    in: inProp,
	    onExited,
	    timeout
	  } = props;
	  const [leaving, setLeaving] = reactExports.useState(false);
	  const rippleClassName = clsx(className, classes.ripple, classes.rippleVisible, pulsate && classes.ripplePulsate);
	  const rippleStyles = {
	    width: rippleSize,
	    height: rippleSize,
	    top: -(rippleSize / 2) + rippleY,
	    left: -(rippleSize / 2) + rippleX
	  };
	  const childClassName = clsx(classes.child, leaving && classes.childLeaving, pulsate && classes.childPulsate);
	  if (!inProp && !leaving) {
	    setLeaving(true);
	  }
	  reactExports.useEffect(() => {
	    if (!inProp && onExited != null) {
	      // react-transition-group#onExited
	      const timeoutId = setTimeout(onExited, timeout);
	      return () => {
	        clearTimeout(timeoutId);
	      };
	    }
	    return undefined;
	  }, [onExited, inProp, timeout]);
	  return /*#__PURE__*/jsxRuntimeExports.jsx("span", {
	    className: rippleClassName,
	    style: rippleStyles,
	    children: /*#__PURE__*/jsxRuntimeExports.jsx("span", {
	      className: childClassName
	    })
	  });
	}

	const touchRippleClasses = generateUtilityClasses('MuiTouchRipple', ['root', 'ripple', 'rippleVisible', 'ripplePulsate', 'child', 'childLeaving', 'childPulsate']);
	var touchRippleClasses$1 = touchRippleClasses;

	const _excluded$k = ["center", "classes", "className"];
	let _$1 = t => t,
	  _t$1,
	  _t2$1,
	  _t3$1,
	  _t4$1;
	const DURATION = 550;
	const DELAY_RIPPLE = 80;
	const enterKeyframe = keyframes(_t$1 || (_t$1 = _$1`
  0% {
    transform: scale(0);
    opacity: 0.1;
  }

  100% {
    transform: scale(1);
    opacity: 0.3;
  }
`));
	const exitKeyframe = keyframes(_t2$1 || (_t2$1 = _$1`
  0% {
    opacity: 1;
  }

  100% {
    opacity: 0;
  }
`));
	const pulsateKeyframe = keyframes(_t3$1 || (_t3$1 = _$1`
  0% {
    transform: scale(1);
  }

  50% {
    transform: scale(0.92);
  }

  100% {
    transform: scale(1);
  }
`));
	const TouchRippleRoot = styled$1('span', {
	  name: 'MuiTouchRipple',
	  slot: 'Root'
	})({
	  overflow: 'hidden',
	  pointerEvents: 'none',
	  position: 'absolute',
	  zIndex: 0,
	  top: 0,
	  right: 0,
	  bottom: 0,
	  left: 0,
	  borderRadius: 'inherit'
	});

	// This `styled()` function invokes keyframes. `styled-components` only supports keyframes
	// in string templates. Do not convert these styles in JS object as it will break.
	const TouchRippleRipple = styled$1(Ripple, {
	  name: 'MuiTouchRipple',
	  slot: 'Ripple'
	})(_t4$1 || (_t4$1 = _$1`
  opacity: 0;
  position: absolute;

  &.${0} {
    opacity: 0.3;
    transform: scale(1);
    animation-name: ${0};
    animation-duration: ${0}ms;
    animation-timing-function: ${0};
  }

  &.${0} {
    animation-duration: ${0}ms;
  }

  & .${0} {
    opacity: 1;
    display: block;
    width: 100%;
    height: 100%;
    border-radius: 50%;
    background-color: currentColor;
  }

  & .${0} {
    opacity: 0;
    animation-name: ${0};
    animation-duration: ${0}ms;
    animation-timing-function: ${0};
  }

  & .${0} {
    position: absolute;
    /* @noflip */
    left: 0px;
    top: 0;
    animation-name: ${0};
    animation-duration: 2500ms;
    animation-timing-function: ${0};
    animation-iteration-count: infinite;
    animation-delay: 200ms;
  }
`), touchRippleClasses$1.rippleVisible, enterKeyframe, DURATION, ({
	  theme
	}) => theme.transitions.easing.easeInOut, touchRippleClasses$1.ripplePulsate, ({
	  theme
	}) => theme.transitions.duration.shorter, touchRippleClasses$1.child, touchRippleClasses$1.childLeaving, exitKeyframe, DURATION, ({
	  theme
	}) => theme.transitions.easing.easeInOut, touchRippleClasses$1.childPulsate, pulsateKeyframe, ({
	  theme
	}) => theme.transitions.easing.easeInOut);

	/**
	 * @ignore - internal component.
	 *
	 * TODO v5: Make private
	 */
	const TouchRipple = /*#__PURE__*/reactExports.forwardRef(function TouchRipple(inProps, ref) {
	  const props = useThemeProps({
	    props: inProps,
	    name: 'MuiTouchRipple'
	  });
	  const {
	      center: centerProp = false,
	      classes = {},
	      className
	    } = props,
	    other = _objectWithoutPropertiesLoose(props, _excluded$k);
	  const [ripples, setRipples] = reactExports.useState([]);
	  const nextKey = reactExports.useRef(0);
	  const rippleCallback = reactExports.useRef(null);
	  reactExports.useEffect(() => {
	    if (rippleCallback.current) {
	      rippleCallback.current();
	      rippleCallback.current = null;
	    }
	  }, [ripples]);

	  // Used to filter out mouse emulated events on mobile.
	  const ignoringMouseDown = reactExports.useRef(false);
	  // We use a timer in order to only show the ripples for touch "click" like events.
	  // We don't want to display the ripple for touch scroll events.
	  const startTimer = useTimeout();

	  // This is the hook called once the previous timeout is ready.
	  const startTimerCommit = reactExports.useRef(null);
	  const container = reactExports.useRef(null);
	  const startCommit = reactExports.useCallback(params => {
	    const {
	      pulsate,
	      rippleX,
	      rippleY,
	      rippleSize,
	      cb
	    } = params;
	    setRipples(oldRipples => [...oldRipples, /*#__PURE__*/jsxRuntimeExports.jsx(TouchRippleRipple, {
	      classes: {
	        ripple: clsx(classes.ripple, touchRippleClasses$1.ripple),
	        rippleVisible: clsx(classes.rippleVisible, touchRippleClasses$1.rippleVisible),
	        ripplePulsate: clsx(classes.ripplePulsate, touchRippleClasses$1.ripplePulsate),
	        child: clsx(classes.child, touchRippleClasses$1.child),
	        childLeaving: clsx(classes.childLeaving, touchRippleClasses$1.childLeaving),
	        childPulsate: clsx(classes.childPulsate, touchRippleClasses$1.childPulsate)
	      },
	      timeout: DURATION,
	      pulsate: pulsate,
	      rippleX: rippleX,
	      rippleY: rippleY,
	      rippleSize: rippleSize
	    }, nextKey.current)]);
	    nextKey.current += 1;
	    rippleCallback.current = cb;
	  }, [classes]);
	  const start = reactExports.useCallback((event = {}, options = {}, cb = () => {}) => {
	    const {
	      pulsate = false,
	      center = centerProp || options.pulsate,
	      fakeElement = false // For test purposes
	    } = options;
	    if ((event == null ? void 0 : event.type) === 'mousedown' && ignoringMouseDown.current) {
	      ignoringMouseDown.current = false;
	      return;
	    }
	    if ((event == null ? void 0 : event.type) === 'touchstart') {
	      ignoringMouseDown.current = true;
	    }
	    const element = fakeElement ? null : container.current;
	    const rect = element ? element.getBoundingClientRect() : {
	      width: 0,
	      height: 0,
	      left: 0,
	      top: 0
	    };

	    // Get the size of the ripple
	    let rippleX;
	    let rippleY;
	    let rippleSize;
	    if (center || event === undefined || event.clientX === 0 && event.clientY === 0 || !event.clientX && !event.touches) {
	      rippleX = Math.round(rect.width / 2);
	      rippleY = Math.round(rect.height / 2);
	    } else {
	      const {
	        clientX,
	        clientY
	      } = event.touches && event.touches.length > 0 ? event.touches[0] : event;
	      rippleX = Math.round(clientX - rect.left);
	      rippleY = Math.round(clientY - rect.top);
	    }
	    if (center) {
	      rippleSize = Math.sqrt((2 * rect.width ** 2 + rect.height ** 2) / 3);

	      // For some reason the animation is broken on Mobile Chrome if the size is even.
	      if (rippleSize % 2 === 0) {
	        rippleSize += 1;
	      }
	    } else {
	      const sizeX = Math.max(Math.abs((element ? element.clientWidth : 0) - rippleX), rippleX) * 2 + 2;
	      const sizeY = Math.max(Math.abs((element ? element.clientHeight : 0) - rippleY), rippleY) * 2 + 2;
	      rippleSize = Math.sqrt(sizeX ** 2 + sizeY ** 2);
	    }

	    // Touche devices
	    if (event != null && event.touches) {
	      // check that this isn't another touchstart due to multitouch
	      // otherwise we will only clear a single timer when unmounting while two
	      // are running
	      if (startTimerCommit.current === null) {
	        // Prepare the ripple effect.
	        startTimerCommit.current = () => {
	          startCommit({
	            pulsate,
	            rippleX,
	            rippleY,
	            rippleSize,
	            cb
	          });
	        };
	        // Delay the execution of the ripple effect.
	        // We have to make a tradeoff with this delay value.
	        startTimer.start(DELAY_RIPPLE, () => {
	          if (startTimerCommit.current) {
	            startTimerCommit.current();
	            startTimerCommit.current = null;
	          }
	        });
	      }
	    } else {
	      startCommit({
	        pulsate,
	        rippleX,
	        rippleY,
	        rippleSize,
	        cb
	      });
	    }
	  }, [centerProp, startCommit, startTimer]);
	  const pulsate = reactExports.useCallback(() => {
	    start({}, {
	      pulsate: true
	    });
	  }, [start]);
	  const stop = reactExports.useCallback((event, cb) => {
	    startTimer.clear();

	    // The touch interaction occurs too quickly.
	    // We still want to show ripple effect.
	    if ((event == null ? void 0 : event.type) === 'touchend' && startTimerCommit.current) {
	      startTimerCommit.current();
	      startTimerCommit.current = null;
	      startTimer.start(0, () => {
	        stop(event, cb);
	      });
	      return;
	    }
	    startTimerCommit.current = null;
	    setRipples(oldRipples => {
	      if (oldRipples.length > 0) {
	        return oldRipples.slice(1);
	      }
	      return oldRipples;
	    });
	    rippleCallback.current = cb;
	  }, [startTimer]);
	  reactExports.useImperativeHandle(ref, () => ({
	    pulsate,
	    start,
	    stop
	  }), [pulsate, start, stop]);
	  return /*#__PURE__*/jsxRuntimeExports.jsx(TouchRippleRoot, _extends$1({
	    className: clsx(touchRippleClasses$1.root, classes.root, className),
	    ref: container
	  }, other, {
	    children: /*#__PURE__*/jsxRuntimeExports.jsx(TransitionGroup$1, {
	      component: null,
	      exit: true,
	      children: ripples
	    })
	  }));
	});
	var TouchRipple$1 = TouchRipple;

	function getButtonBaseUtilityClass(slot) {
	  return generateUtilityClass('MuiButtonBase', slot);
	}
	const buttonBaseClasses = generateUtilityClasses('MuiButtonBase', ['root', 'disabled', 'focusVisible']);
	var buttonBaseClasses$1 = buttonBaseClasses;

	const _excluded$j = ["action", "centerRipple", "children", "className", "component", "disabled", "disableRipple", "disableTouchRipple", "focusRipple", "focusVisibleClassName", "LinkComponent", "onBlur", "onClick", "onContextMenu", "onDragLeave", "onFocus", "onFocusVisible", "onKeyDown", "onKeyUp", "onMouseDown", "onMouseLeave", "onMouseUp", "onTouchEnd", "onTouchMove", "onTouchStart", "tabIndex", "TouchRippleProps", "touchRippleRef", "type"];
	const useUtilityClasses$f = ownerState => {
	  const {
	    disabled,
	    focusVisible,
	    focusVisibleClassName,
	    classes
	  } = ownerState;
	  const slots = {
	    root: ['root', disabled && 'disabled', focusVisible && 'focusVisible']
	  };
	  const composedClasses = composeClasses(slots, getButtonBaseUtilityClass, classes);
	  if (focusVisible && focusVisibleClassName) {
	    composedClasses.root += ` ${focusVisibleClassName}`;
	  }
	  return composedClasses;
	};
	const ButtonBaseRoot = styled$1('button', {
	  name: 'MuiButtonBase',
	  slot: 'Root',
	  overridesResolver: (props, styles) => styles.root
	})({
	  display: 'inline-flex',
	  alignItems: 'center',
	  justifyContent: 'center',
	  position: 'relative',
	  boxSizing: 'border-box',
	  WebkitTapHighlightColor: 'transparent',
	  backgroundColor: 'transparent',
	  // Reset default value
	  // We disable the focus ring for mouse, touch and keyboard users.
	  outline: 0,
	  border: 0,
	  margin: 0,
	  // Remove the margin in Safari
	  borderRadius: 0,
	  padding: 0,
	  // Remove the padding in Firefox
	  cursor: 'pointer',
	  userSelect: 'none',
	  verticalAlign: 'middle',
	  MozAppearance: 'none',
	  // Reset
	  WebkitAppearance: 'none',
	  // Reset
	  textDecoration: 'none',
	  // So we take precedent over the style of a native <a /> element.
	  color: 'inherit',
	  '&::-moz-focus-inner': {
	    borderStyle: 'none' // Remove Firefox dotted outline.
	  },
	  [`&.${buttonBaseClasses$1.disabled}`]: {
	    pointerEvents: 'none',
	    // Disable link interactions
	    cursor: 'default'
	  },
	  '@media print': {
	    colorAdjust: 'exact'
	  }
	});

	/**
	 * `ButtonBase` contains as few styles as possible.
	 * It aims to be a simple building block for creating a button.
	 * It contains a load of style reset and some focus/ripple logic.
	 */
	const ButtonBase = /*#__PURE__*/reactExports.forwardRef(function ButtonBase(inProps, ref) {
	  const props = useThemeProps({
	    props: inProps,
	    name: 'MuiButtonBase'
	  });
	  const {
	      action,
	      centerRipple = false,
	      children,
	      className,
	      component = 'button',
	      disabled = false,
	      disableRipple = false,
	      disableTouchRipple = false,
	      focusRipple = false,
	      LinkComponent = 'a',
	      onBlur,
	      onClick,
	      onContextMenu,
	      onDragLeave,
	      onFocus,
	      onFocusVisible,
	      onKeyDown,
	      onKeyUp,
	      onMouseDown,
	      onMouseLeave,
	      onMouseUp,
	      onTouchEnd,
	      onTouchMove,
	      onTouchStart,
	      tabIndex = 0,
	      TouchRippleProps,
	      touchRippleRef,
	      type
	    } = props,
	    other = _objectWithoutPropertiesLoose(props, _excluded$j);
	  const buttonRef = reactExports.useRef(null);
	  const rippleRef = reactExports.useRef(null);
	  const handleRippleRef = useForkRef(rippleRef, touchRippleRef);
	  const {
	    isFocusVisibleRef,
	    onFocus: handleFocusVisible,
	    onBlur: handleBlurVisible,
	    ref: focusVisibleRef
	  } = useIsFocusVisible();
	  const [focusVisible, setFocusVisible] = reactExports.useState(false);
	  if (disabled && focusVisible) {
	    setFocusVisible(false);
	  }
	  reactExports.useImperativeHandle(action, () => ({
	    focusVisible: () => {
	      setFocusVisible(true);
	      buttonRef.current.focus();
	    }
	  }), []);
	  const [mountedState, setMountedState] = reactExports.useState(false);
	  reactExports.useEffect(() => {
	    setMountedState(true);
	  }, []);
	  const enableTouchRipple = mountedState && !disableRipple && !disabled;
	  reactExports.useEffect(() => {
	    if (focusVisible && focusRipple && !disableRipple && mountedState) {
	      rippleRef.current.pulsate();
	    }
	  }, [disableRipple, focusRipple, focusVisible, mountedState]);
	  function useRippleHandler(rippleAction, eventCallback, skipRippleAction = disableTouchRipple) {
	    return useEventCallback(event => {
	      if (eventCallback) {
	        eventCallback(event);
	      }
	      const ignore = skipRippleAction;
	      if (!ignore && rippleRef.current) {
	        rippleRef.current[rippleAction](event);
	      }
	      return true;
	    });
	  }
	  const handleMouseDown = useRippleHandler('start', onMouseDown);
	  const handleContextMenu = useRippleHandler('stop', onContextMenu);
	  const handleDragLeave = useRippleHandler('stop', onDragLeave);
	  const handleMouseUp = useRippleHandler('stop', onMouseUp);
	  const handleMouseLeave = useRippleHandler('stop', event => {
	    if (focusVisible) {
	      event.preventDefault();
	    }
	    if (onMouseLeave) {
	      onMouseLeave(event);
	    }
	  });
	  const handleTouchStart = useRippleHandler('start', onTouchStart);
	  const handleTouchEnd = useRippleHandler('stop', onTouchEnd);
	  const handleTouchMove = useRippleHandler('stop', onTouchMove);
	  const handleBlur = useRippleHandler('stop', event => {
	    handleBlurVisible(event);
	    if (isFocusVisibleRef.current === false) {
	      setFocusVisible(false);
	    }
	    if (onBlur) {
	      onBlur(event);
	    }
	  }, false);
	  const handleFocus = useEventCallback(event => {
	    // Fix for https://github.com/facebook/react/issues/7769
	    if (!buttonRef.current) {
	      buttonRef.current = event.currentTarget;
	    }
	    handleFocusVisible(event);
	    if (isFocusVisibleRef.current === true) {
	      setFocusVisible(true);
	      if (onFocusVisible) {
	        onFocusVisible(event);
	      }
	    }
	    if (onFocus) {
	      onFocus(event);
	    }
	  });
	  const isNonNativeButton = () => {
	    const button = buttonRef.current;
	    return component && component !== 'button' && !(button.tagName === 'A' && button.href);
	  };

	  /**
	   * IE11 shim for https://developer.mozilla.org/en-US/docs/Web/API/KeyboardEvent/repeat
	   */
	  const keydownRef = reactExports.useRef(false);
	  const handleKeyDown = useEventCallback(event => {
	    // Check if key is already down to avoid repeats being counted as multiple activations
	    if (focusRipple && !keydownRef.current && focusVisible && rippleRef.current && event.key === ' ') {
	      keydownRef.current = true;
	      rippleRef.current.stop(event, () => {
	        rippleRef.current.start(event);
	      });
	    }
	    if (event.target === event.currentTarget && isNonNativeButton() && event.key === ' ') {
	      event.preventDefault();
	    }
	    if (onKeyDown) {
	      onKeyDown(event);
	    }

	    // Keyboard accessibility for non interactive elements
	    if (event.target === event.currentTarget && isNonNativeButton() && event.key === 'Enter' && !disabled) {
	      event.preventDefault();
	      if (onClick) {
	        onClick(event);
	      }
	    }
	  });
	  const handleKeyUp = useEventCallback(event => {
	    // calling preventDefault in keyUp on a <button> will not dispatch a click event if Space is pressed
	    // https://codesandbox.io/p/sandbox/button-keyup-preventdefault-dn7f0
	    if (focusRipple && event.key === ' ' && rippleRef.current && focusVisible && !event.defaultPrevented) {
	      keydownRef.current = false;
	      rippleRef.current.stop(event, () => {
	        rippleRef.current.pulsate(event);
	      });
	    }
	    if (onKeyUp) {
	      onKeyUp(event);
	    }

	    // Keyboard accessibility for non interactive elements
	    if (onClick && event.target === event.currentTarget && isNonNativeButton() && event.key === ' ' && !event.defaultPrevented) {
	      onClick(event);
	    }
	  });
	  let ComponentProp = component;
	  if (ComponentProp === 'button' && (other.href || other.to)) {
	    ComponentProp = LinkComponent;
	  }
	  const buttonProps = {};
	  if (ComponentProp === 'button') {
	    buttonProps.type = type === undefined ? 'button' : type;
	    buttonProps.disabled = disabled;
	  } else {
	    if (!other.href && !other.to) {
	      buttonProps.role = 'button';
	    }
	    if (disabled) {
	      buttonProps['aria-disabled'] = disabled;
	    }
	  }
	  const handleRef = useForkRef(ref, focusVisibleRef, buttonRef);
	  const ownerState = _extends$1({}, props, {
	    centerRipple,
	    component,
	    disabled,
	    disableRipple,
	    disableTouchRipple,
	    focusRipple,
	    tabIndex,
	    focusVisible
	  });
	  const classes = useUtilityClasses$f(ownerState);
	  return /*#__PURE__*/jsxRuntimeExports.jsxs(ButtonBaseRoot, _extends$1({
	    as: ComponentProp,
	    className: clsx(classes.root, className),
	    ownerState: ownerState,
	    onBlur: handleBlur,
	    onClick: onClick,
	    onContextMenu: handleContextMenu,
	    onFocus: handleFocus,
	    onKeyDown: handleKeyDown,
	    onKeyUp: handleKeyUp,
	    onMouseDown: handleMouseDown,
	    onMouseLeave: handleMouseLeave,
	    onMouseUp: handleMouseUp,
	    onDragLeave: handleDragLeave,
	    onTouchEnd: handleTouchEnd,
	    onTouchMove: handleTouchMove,
	    onTouchStart: handleTouchStart,
	    ref: handleRef,
	    tabIndex: disabled ? -1 : tabIndex,
	    type: type
	  }, buttonProps, other, {
	    children: [children, enableTouchRipple ? /*#__PURE__*/
	    /* TouchRipple is only needed client-side, x2 boost on the server. */
	    jsxRuntimeExports.jsx(TouchRipple$1, _extends$1({
	      ref: handleRippleRef,
	      center: centerRipple
	    }, TouchRippleProps)) : null]
	  }));
	});
	var ButtonBase$1 = ButtonBase;

	function getIconButtonUtilityClass(slot) {
	  return generateUtilityClass('MuiIconButton', slot);
	}
	const iconButtonClasses = generateUtilityClasses('MuiIconButton', ['root', 'disabled', 'colorInherit', 'colorPrimary', 'colorSecondary', 'colorError', 'colorInfo', 'colorSuccess', 'colorWarning', 'edgeStart', 'edgeEnd', 'sizeSmall', 'sizeMedium', 'sizeLarge']);
	var iconButtonClasses$1 = iconButtonClasses;

	const _excluded$i = ["edge", "children", "className", "color", "disabled", "disableFocusRipple", "size"];
	const useUtilityClasses$e = ownerState => {
	  const {
	    classes,
	    disabled,
	    color,
	    edge,
	    size
	  } = ownerState;
	  const slots = {
	    root: ['root', disabled && 'disabled', color !== 'default' && `color${capitalize$2(color)}`, edge && `edge${capitalize$2(edge)}`, `size${capitalize$2(size)}`]
	  };
	  return composeClasses(slots, getIconButtonUtilityClass, classes);
	};
	const IconButtonRoot = styled$1(ButtonBase$1, {
	  name: 'MuiIconButton',
	  slot: 'Root',
	  overridesResolver: (props, styles) => {
	    const {
	      ownerState
	    } = props;
	    return [styles.root, ownerState.color !== 'default' && styles[`color${capitalize$2(ownerState.color)}`], ownerState.edge && styles[`edge${capitalize$2(ownerState.edge)}`], styles[`size${capitalize$2(ownerState.size)}`]];
	  }
	})(({
	  theme,
	  ownerState
	}) => _extends$1({
	  textAlign: 'center',
	  flex: '0 0 auto',
	  fontSize: theme.typography.pxToRem(24),
	  padding: 8,
	  borderRadius: '50%',
	  overflow: 'visible',
	  // Explicitly set the default value to solve a bug on IE11.
	  color: (theme.vars || theme).palette.action.active,
	  transition: theme.transitions.create('background-color', {
	    duration: theme.transitions.duration.shortest
	  })
	}, !ownerState.disableRipple && {
	  '&:hover': {
	    backgroundColor: theme.vars ? `rgba(${theme.vars.palette.action.activeChannel} / ${theme.vars.palette.action.hoverOpacity})` : colorManipulatorExports.alpha(theme.palette.action.active, theme.palette.action.hoverOpacity),
	    // Reset on touch devices, it doesn't add specificity
	    '@media (hover: none)': {
	      backgroundColor: 'transparent'
	    }
	  }
	}, ownerState.edge === 'start' && {
	  marginLeft: ownerState.size === 'small' ? -3 : -12
	}, ownerState.edge === 'end' && {
	  marginRight: ownerState.size === 'small' ? -3 : -12
	}), ({
	  theme,
	  ownerState
	}) => {
	  var _palette;
	  const palette = (_palette = (theme.vars || theme).palette) == null ? void 0 : _palette[ownerState.color];
	  return _extends$1({}, ownerState.color === 'inherit' && {
	    color: 'inherit'
	  }, ownerState.color !== 'inherit' && ownerState.color !== 'default' && _extends$1({
	    color: palette == null ? void 0 : palette.main
	  }, !ownerState.disableRipple && {
	    '&:hover': _extends$1({}, palette && {
	      backgroundColor: theme.vars ? `rgba(${palette.mainChannel} / ${theme.vars.palette.action.hoverOpacity})` : colorManipulatorExports.alpha(palette.main, theme.palette.action.hoverOpacity)
	    }, {
	      // Reset on touch devices, it doesn't add specificity
	      '@media (hover: none)': {
	        backgroundColor: 'transparent'
	      }
	    })
	  }), ownerState.size === 'small' && {
	    padding: 5,
	    fontSize: theme.typography.pxToRem(18)
	  }, ownerState.size === 'large' && {
	    padding: 12,
	    fontSize: theme.typography.pxToRem(28)
	  }, {
	    [`&.${iconButtonClasses$1.disabled}`]: {
	      backgroundColor: 'transparent',
	      color: (theme.vars || theme).palette.action.disabled
	    }
	  });
	});

	/**
	 * Refer to the [Icons](/material-ui/icons/) section of the documentation
	 * regarding the available icon options.
	 */
	const IconButton = /*#__PURE__*/reactExports.forwardRef(function IconButton(inProps, ref) {
	  const props = useThemeProps({
	    props: inProps,
	    name: 'MuiIconButton'
	  });
	  const {
	      edge = false,
	      children,
	      className,
	      color = 'default',
	      disabled = false,
	      disableFocusRipple = false,
	      size = 'medium'
	    } = props,
	    other = _objectWithoutPropertiesLoose(props, _excluded$i);
	  const ownerState = _extends$1({}, props, {
	    edge,
	    color,
	    disabled,
	    disableFocusRipple,
	    size
	  });
	  const classes = useUtilityClasses$e(ownerState);
	  return /*#__PURE__*/jsxRuntimeExports.jsx(IconButtonRoot, _extends$1({
	    className: clsx(classes.root, className),
	    centerRipple: true,
	    focusRipple: !disableFocusRipple,
	    disabled: disabled,
	    ref: ref
	  }, other, {
	    ownerState: ownerState,
	    children: children
	  }));
	});
	var IconButton$1 = IconButton;

	function getAppBarUtilityClass(slot) {
	  return generateUtilityClass('MuiAppBar', slot);
	}
	generateUtilityClasses('MuiAppBar', ['root', 'positionFixed', 'positionAbsolute', 'positionSticky', 'positionStatic', 'positionRelative', 'colorDefault', 'colorPrimary', 'colorSecondary', 'colorInherit', 'colorTransparent', 'colorError', 'colorInfo', 'colorSuccess', 'colorWarning']);

	const _excluded$h = ["className", "color", "enableColorOnDark", "position"];
	const useUtilityClasses$d = ownerState => {
	  const {
	    color,
	    position,
	    classes
	  } = ownerState;
	  const slots = {
	    root: ['root', `color${capitalize$2(color)}`, `position${capitalize$2(position)}`]
	  };
	  return composeClasses(slots, getAppBarUtilityClass, classes);
	};

	// var2 is the fallback.
	// Ex. var1: 'var(--a)', var2: 'var(--b)'; return: 'var(--a, var(--b))'
	const joinVars = (var1, var2) => var1 ? `${var1 == null ? void 0 : var1.replace(')', '')}, ${var2})` : var2;
	const AppBarRoot = styled$1(Paper$1, {
	  name: 'MuiAppBar',
	  slot: 'Root',
	  overridesResolver: (props, styles) => {
	    const {
	      ownerState
	    } = props;
	    return [styles.root, styles[`position${capitalize$2(ownerState.position)}`], styles[`color${capitalize$2(ownerState.color)}`]];
	  }
	})(({
	  theme,
	  ownerState
	}) => {
	  const backgroundColorDefault = theme.palette.mode === 'light' ? theme.palette.grey[100] : theme.palette.grey[900];
	  return _extends$1({
	    display: 'flex',
	    flexDirection: 'column',
	    width: '100%',
	    boxSizing: 'border-box',
	    // Prevent padding issue with the Modal and fixed positioned AppBar.
	    flexShrink: 0
	  }, ownerState.position === 'fixed' && {
	    position: 'fixed',
	    zIndex: (theme.vars || theme).zIndex.appBar,
	    top: 0,
	    left: 'auto',
	    right: 0,
	    '@media print': {
	      // Prevent the app bar to be visible on each printed page.
	      position: 'absolute'
	    }
	  }, ownerState.position === 'absolute' && {
	    position: 'absolute',
	    zIndex: (theme.vars || theme).zIndex.appBar,
	    top: 0,
	    left: 'auto',
	    right: 0
	  }, ownerState.position === 'sticky' && {
	    // ⚠️ sticky is not supported by IE11.
	    position: 'sticky',
	    zIndex: (theme.vars || theme).zIndex.appBar,
	    top: 0,
	    left: 'auto',
	    right: 0
	  }, ownerState.position === 'static' && {
	    position: 'static'
	  }, ownerState.position === 'relative' && {
	    position: 'relative'
	  }, !theme.vars && _extends$1({}, ownerState.color === 'default' && {
	    backgroundColor: backgroundColorDefault,
	    color: theme.palette.getContrastText(backgroundColorDefault)
	  }, ownerState.color && ownerState.color !== 'default' && ownerState.color !== 'inherit' && ownerState.color !== 'transparent' && {
	    backgroundColor: theme.palette[ownerState.color].main,
	    color: theme.palette[ownerState.color].contrastText
	  }, ownerState.color === 'inherit' && {
	    color: 'inherit'
	  }, theme.palette.mode === 'dark' && !ownerState.enableColorOnDark && {
	    backgroundColor: null,
	    color: null
	  }, ownerState.color === 'transparent' && _extends$1({
	    backgroundColor: 'transparent',
	    color: 'inherit'
	  }, theme.palette.mode === 'dark' && {
	    backgroundImage: 'none'
	  })), theme.vars && _extends$1({}, ownerState.color === 'default' && {
	    '--AppBar-background': ownerState.enableColorOnDark ? theme.vars.palette.AppBar.defaultBg : joinVars(theme.vars.palette.AppBar.darkBg, theme.vars.palette.AppBar.defaultBg),
	    '--AppBar-color': ownerState.enableColorOnDark ? theme.vars.palette.text.primary : joinVars(theme.vars.palette.AppBar.darkColor, theme.vars.palette.text.primary)
	  }, ownerState.color && !ownerState.color.match(/^(default|inherit|transparent)$/) && {
	    '--AppBar-background': ownerState.enableColorOnDark ? theme.vars.palette[ownerState.color].main : joinVars(theme.vars.palette.AppBar.darkBg, theme.vars.palette[ownerState.color].main),
	    '--AppBar-color': ownerState.enableColorOnDark ? theme.vars.palette[ownerState.color].contrastText : joinVars(theme.vars.palette.AppBar.darkColor, theme.vars.palette[ownerState.color].contrastText)
	  }, {
	    backgroundColor: 'var(--AppBar-background)',
	    color: ownerState.color === 'inherit' ? 'inherit' : 'var(--AppBar-color)'
	  }, ownerState.color === 'transparent' && {
	    backgroundImage: 'none',
	    backgroundColor: 'transparent',
	    color: 'inherit'
	  }));
	});
	const AppBar = /*#__PURE__*/reactExports.forwardRef(function AppBar(inProps, ref) {
	  const props = useThemeProps({
	    props: inProps,
	    name: 'MuiAppBar'
	  });
	  const {
	      className,
	      color = 'primary',
	      enableColorOnDark = false,
	      position = 'fixed'
	    } = props,
	    other = _objectWithoutPropertiesLoose(props, _excluded$h);
	  const ownerState = _extends$1({}, props, {
	    color,
	    position,
	    enableColorOnDark
	  });
	  const classes = useUtilityClasses$d(ownerState);
	  return /*#__PURE__*/jsxRuntimeExports.jsx(AppBarRoot, _extends$1({
	    square: true,
	    component: "header",
	    ownerState: ownerState,
	    elevation: 4,
	    className: clsx(classes.root, className, position === 'fixed' && 'mui-fixed'),
	    ref: ref
	  }, other));
	});
	var AppBar$1 = AppBar;

	// Inspired by https://github.com/focus-trap/tabbable
	const candidatesSelector = ['input', 'select', 'textarea', 'a[href]', 'button', '[tabindex]', 'audio[controls]', 'video[controls]', '[contenteditable]:not([contenteditable="false"])'].join(',');
	function getTabIndex(node) {
	  const tabindexAttr = parseInt(node.getAttribute('tabindex') || '', 10);
	  if (!Number.isNaN(tabindexAttr)) {
	    return tabindexAttr;
	  }

	  // Browsers do not return `tabIndex` correctly for contentEditable nodes;
	  // https://bugs.chromium.org/p/chromium/issues/detail?id=661108&q=contenteditable%20tabindex&can=2
	  // so if they don't have a tabindex attribute specifically set, assume it's 0.
	  // in Chrome, <details/>, <audio controls/> and <video controls/> elements get a default
	  //  `tabIndex` of -1 when the 'tabindex' attribute isn't specified in the DOM,
	  //  yet they are still part of the regular tab order; in FF, they get a default
	  //  `tabIndex` of 0; since Chrome still puts those elements in the regular tab
	  //  order, consider their tab index to be 0.
	  if (node.contentEditable === 'true' || (node.nodeName === 'AUDIO' || node.nodeName === 'VIDEO' || node.nodeName === 'DETAILS') && node.getAttribute('tabindex') === null) {
	    return 0;
	  }
	  return node.tabIndex;
	}
	function isNonTabbableRadio(node) {
	  if (node.tagName !== 'INPUT' || node.type !== 'radio') {
	    return false;
	  }
	  if (!node.name) {
	    return false;
	  }
	  const getRadio = selector => node.ownerDocument.querySelector(`input[type="radio"]${selector}`);
	  let roving = getRadio(`[name="${node.name}"]:checked`);
	  if (!roving) {
	    roving = getRadio(`[name="${node.name}"]`);
	  }
	  return roving !== node;
	}
	function isNodeMatchingSelectorFocusable(node) {
	  if (node.disabled || node.tagName === 'INPUT' && node.type === 'hidden' || isNonTabbableRadio(node)) {
	    return false;
	  }
	  return true;
	}
	function defaultGetTabbable(root) {
	  const regularTabNodes = [];
	  const orderedTabNodes = [];
	  Array.from(root.querySelectorAll(candidatesSelector)).forEach((node, i) => {
	    const nodeTabIndex = getTabIndex(node);
	    if (nodeTabIndex === -1 || !isNodeMatchingSelectorFocusable(node)) {
	      return;
	    }
	    if (nodeTabIndex === 0) {
	      regularTabNodes.push(node);
	    } else {
	      orderedTabNodes.push({
	        documentOrder: i,
	        tabIndex: nodeTabIndex,
	        node: node
	      });
	    }
	  });
	  return orderedTabNodes.sort((a, b) => a.tabIndex === b.tabIndex ? a.documentOrder - b.documentOrder : a.tabIndex - b.tabIndex).map(a => a.node).concat(regularTabNodes);
	}
	function defaultIsEnabled() {
	  return true;
	}

	/**
	 * Utility component that locks focus inside the component.
	 *
	 * Demos:
	 *
	 * - [Focus Trap](https://mui.com/base-ui/react-focus-trap/)
	 *
	 * API:
	 *
	 * - [FocusTrap API](https://mui.com/base-ui/react-focus-trap/components-api/#focus-trap)
	 */
	function FocusTrap(props) {
	  const {
	    children,
	    disableAutoFocus = false,
	    disableEnforceFocus = false,
	    disableRestoreFocus = false,
	    getTabbable = defaultGetTabbable,
	    isEnabled = defaultIsEnabled,
	    open
	  } = props;
	  const ignoreNextEnforceFocus = reactExports.useRef(false);
	  const sentinelStart = reactExports.useRef(null);
	  const sentinelEnd = reactExports.useRef(null);
	  const nodeToRestore = reactExports.useRef(null);
	  const reactFocusEventTarget = reactExports.useRef(null);
	  // This variable is useful when disableAutoFocus is true.
	  // It waits for the active element to move into the component to activate.
	  const activated = reactExports.useRef(false);
	  const rootRef = reactExports.useRef(null);
	  // @ts-expect-error TODO upstream fix
	  const handleRef = useForkRef(children.ref, rootRef);
	  const lastKeydown = reactExports.useRef(null);
	  reactExports.useEffect(() => {
	    // We might render an empty child.
	    if (!open || !rootRef.current) {
	      return;
	    }
	    activated.current = !disableAutoFocus;
	  }, [disableAutoFocus, open]);
	  reactExports.useEffect(() => {
	    // We might render an empty child.
	    if (!open || !rootRef.current) {
	      return;
	    }
	    const doc = ownerDocument(rootRef.current);
	    if (!rootRef.current.contains(doc.activeElement)) {
	      if (!rootRef.current.hasAttribute('tabIndex')) {
	        rootRef.current.setAttribute('tabIndex', '-1');
	      }
	      if (activated.current) {
	        rootRef.current.focus();
	      }
	    }
	    return () => {
	      // restoreLastFocus()
	      if (!disableRestoreFocus) {
	        // In IE11 it is possible for document.activeElement to be null resulting
	        // in nodeToRestore.current being null.
	        // Not all elements in IE11 have a focus method.
	        // Once IE11 support is dropped the focus() call can be unconditional.
	        if (nodeToRestore.current && nodeToRestore.current.focus) {
	          ignoreNextEnforceFocus.current = true;
	          nodeToRestore.current.focus();
	        }
	        nodeToRestore.current = null;
	      }
	    };
	    // Missing `disableRestoreFocus` which is fine.
	    // We don't support changing that prop on an open FocusTrap
	    // eslint-disable-next-line react-hooks/exhaustive-deps
	  }, [open]);
	  reactExports.useEffect(() => {
	    // We might render an empty child.
	    if (!open || !rootRef.current) {
	      return;
	    }
	    const doc = ownerDocument(rootRef.current);
	    const loopFocus = nativeEvent => {
	      lastKeydown.current = nativeEvent;
	      if (disableEnforceFocus || !isEnabled() || nativeEvent.key !== 'Tab') {
	        return;
	      }

	      // Make sure the next tab starts from the right place.
	      // doc.activeElement refers to the origin.
	      if (doc.activeElement === rootRef.current && nativeEvent.shiftKey) {
	        // We need to ignore the next contain as
	        // it will try to move the focus back to the rootRef element.
	        ignoreNextEnforceFocus.current = true;
	        if (sentinelEnd.current) {
	          sentinelEnd.current.focus();
	        }
	      }
	    };
	    const contain = () => {
	      const rootElement = rootRef.current;

	      // Cleanup functions are executed lazily in React 17.
	      // Contain can be called between the component being unmounted and its cleanup function being run.
	      if (rootElement === null) {
	        return;
	      }
	      if (!doc.hasFocus() || !isEnabled() || ignoreNextEnforceFocus.current) {
	        ignoreNextEnforceFocus.current = false;
	        return;
	      }

	      // The focus is already inside
	      if (rootElement.contains(doc.activeElement)) {
	        return;
	      }

	      // The disableEnforceFocus is set and the focus is outside of the focus trap (and sentinel nodes)
	      if (disableEnforceFocus && doc.activeElement !== sentinelStart.current && doc.activeElement !== sentinelEnd.current) {
	        return;
	      }

	      // if the focus event is not coming from inside the children's react tree, reset the refs
	      if (doc.activeElement !== reactFocusEventTarget.current) {
	        reactFocusEventTarget.current = null;
	      } else if (reactFocusEventTarget.current !== null) {
	        return;
	      }
	      if (!activated.current) {
	        return;
	      }
	      let tabbable = [];
	      if (doc.activeElement === sentinelStart.current || doc.activeElement === sentinelEnd.current) {
	        tabbable = getTabbable(rootRef.current);
	      }

	      // one of the sentinel nodes was focused, so move the focus
	      // to the first/last tabbable element inside the focus trap
	      if (tabbable.length > 0) {
	        var _lastKeydown$current, _lastKeydown$current2;
	        const isShiftTab = Boolean(((_lastKeydown$current = lastKeydown.current) == null ? void 0 : _lastKeydown$current.shiftKey) && ((_lastKeydown$current2 = lastKeydown.current) == null ? void 0 : _lastKeydown$current2.key) === 'Tab');
	        const focusNext = tabbable[0];
	        const focusPrevious = tabbable[tabbable.length - 1];
	        if (typeof focusNext !== 'string' && typeof focusPrevious !== 'string') {
	          if (isShiftTab) {
	            focusPrevious.focus();
	          } else {
	            focusNext.focus();
	          }
	        }
	        // no tabbable elements in the trap focus or the focus was outside of the focus trap
	      } else {
	        rootElement.focus();
	      }
	    };
	    doc.addEventListener('focusin', contain);
	    doc.addEventListener('keydown', loopFocus, true);

	    // With Edge, Safari and Firefox, no focus related events are fired when the focused area stops being a focused area.
	    // for example https://bugzilla.mozilla.org/show_bug.cgi?id=559561.
	    // Instead, we can look if the active element was restored on the BODY element.
	    //
	    // The whatwg spec defines how the browser should behave but does not explicitly mention any events:
	    // https://html.spec.whatwg.org/multipage/interaction.html#focus-fixup-rule.
	    const interval = setInterval(() => {
	      if (doc.activeElement && doc.activeElement.tagName === 'BODY') {
	        contain();
	      }
	    }, 50);
	    return () => {
	      clearInterval(interval);
	      doc.removeEventListener('focusin', contain);
	      doc.removeEventListener('keydown', loopFocus, true);
	    };
	  }, [disableAutoFocus, disableEnforceFocus, disableRestoreFocus, isEnabled, open, getTabbable]);
	  const onFocus = event => {
	    if (nodeToRestore.current === null) {
	      nodeToRestore.current = event.relatedTarget;
	    }
	    activated.current = true;
	    reactFocusEventTarget.current = event.target;
	    const childrenPropsHandler = children.props.onFocus;
	    if (childrenPropsHandler) {
	      childrenPropsHandler(event);
	    }
	  };
	  const handleFocusSentinel = event => {
	    if (nodeToRestore.current === null) {
	      nodeToRestore.current = event.relatedTarget;
	    }
	    activated.current = true;
	  };
	  return /*#__PURE__*/jsxRuntimeExports.jsxs(reactExports.Fragment, {
	    children: [/*#__PURE__*/jsxRuntimeExports.jsx("div", {
	      tabIndex: open ? 0 : -1,
	      onFocus: handleFocusSentinel,
	      ref: sentinelStart,
	      "data-testid": "sentinelStart"
	    }), /*#__PURE__*/reactExports.cloneElement(children, {
	      ref: handleRef,
	      onFocus
	    }), /*#__PURE__*/jsxRuntimeExports.jsx("div", {
	      tabIndex: open ? 0 : -1,
	      onFocus: handleFocusSentinel,
	      ref: sentinelEnd,
	      "data-testid": "sentinelEnd"
	    })]
	  });
	}

	function getContainer$1(container) {
	  return typeof container === 'function' ? container() : container;
	}

	/**
	 * Portals provide a first-class way to render children into a DOM node
	 * that exists outside the DOM hierarchy of the parent component.
	 *
	 * Demos:
	 *
	 * - [Portal](https://mui.com/base-ui/react-portal/)
	 *
	 * API:
	 *
	 * - [Portal API](https://mui.com/base-ui/react-portal/components-api/#portal)
	 */
	const Portal = /*#__PURE__*/reactExports.forwardRef(function Portal(props, forwardedRef) {
	  const {
	    children,
	    container,
	    disablePortal = false
	  } = props;
	  const [mountNode, setMountNode] = reactExports.useState(null);
	  // @ts-expect-error TODO upstream fix
	  const handleRef = useForkRef(/*#__PURE__*/ /*#__PURE__*/reactExports.isValidElement(children) ? children.ref : null, forwardedRef);
	  useEnhancedEffect$1(() => {
	    if (!disablePortal) {
	      setMountNode(getContainer$1(container) || document.body);
	    }
	  }, [container, disablePortal]);
	  useEnhancedEffect$1(() => {
	    if (mountNode && !disablePortal) {
	      setRef(forwardedRef, mountNode);
	      return () => {
	        setRef(forwardedRef, null);
	      };
	    }
	    return undefined;
	  }, [forwardedRef, mountNode, disablePortal]);
	  if (disablePortal) {
	    if (/*#__PURE__*/reactExports.isValidElement(children)) {
	      const newProps = {
	        ref: handleRef
	      };
	      return /*#__PURE__*/reactExports.cloneElement(children, newProps);
	    }
	    return /*#__PURE__*/jsxRuntimeExports.jsx(reactExports.Fragment, {
	      children: children
	    });
	  }
	  return /*#__PURE__*/jsxRuntimeExports.jsx(reactExports.Fragment, {
	    children: mountNode ? /*#__PURE__*/reactDomExports.createPortal(children, mountNode) : mountNode
	  });
	});

	// Is a vertical scrollbar displayed?
	function isOverflowing(container) {
	  const doc = ownerDocument(container);
	  if (doc.body === container) {
	    return ownerWindow(container).innerWidth > doc.documentElement.clientWidth;
	  }
	  return container.scrollHeight > container.clientHeight;
	}
	function ariaHidden(element, show) {
	  if (show) {
	    element.setAttribute('aria-hidden', 'true');
	  } else {
	    element.removeAttribute('aria-hidden');
	  }
	}
	function getPaddingRight(element) {
	  return parseInt(ownerWindow(element).getComputedStyle(element).paddingRight, 10) || 0;
	}
	function isAriaHiddenForbiddenOnElement(element) {
	  // The forbidden HTML tags are the ones from ARIA specification that
	  // can be children of body and can't have aria-hidden attribute.
	  // cf. https://www.w3.org/TR/html-aria/#docconformance
	  const forbiddenTagNames = ['TEMPLATE', 'SCRIPT', 'STYLE', 'LINK', 'MAP', 'META', 'NOSCRIPT', 'PICTURE', 'COL', 'COLGROUP', 'PARAM', 'SLOT', 'SOURCE', 'TRACK'];
	  const isForbiddenTagName = forbiddenTagNames.indexOf(element.tagName) !== -1;
	  const isInputHidden = element.tagName === 'INPUT' && element.getAttribute('type') === 'hidden';
	  return isForbiddenTagName || isInputHidden;
	}
	function ariaHiddenSiblings(container, mountElement, currentElement, elementsToExclude, show) {
	  const blacklist = [mountElement, currentElement, ...elementsToExclude];
	  [].forEach.call(container.children, element => {
	    const isNotExcludedElement = blacklist.indexOf(element) === -1;
	    const isNotForbiddenElement = !isAriaHiddenForbiddenOnElement(element);
	    if (isNotExcludedElement && isNotForbiddenElement) {
	      ariaHidden(element, show);
	    }
	  });
	}
	function findIndexOf(items, callback) {
	  let idx = -1;
	  items.some((item, index) => {
	    if (callback(item)) {
	      idx = index;
	      return true;
	    }
	    return false;
	  });
	  return idx;
	}
	function handleContainer(containerInfo, props) {
	  const restoreStyle = [];
	  const container = containerInfo.container;
	  if (!props.disableScrollLock) {
	    if (isOverflowing(container)) {
	      // Compute the size before applying overflow hidden to avoid any scroll jumps.
	      const scrollbarSize = getScrollbarSize(ownerDocument(container));
	      restoreStyle.push({
	        value: container.style.paddingRight,
	        property: 'padding-right',
	        el: container
	      });
	      // Use computed style, here to get the real padding to add our scrollbar width.
	      container.style.paddingRight = `${getPaddingRight(container) + scrollbarSize}px`;

	      // .mui-fixed is a global helper.
	      const fixedElements = ownerDocument(container).querySelectorAll('.mui-fixed');
	      [].forEach.call(fixedElements, element => {
	        restoreStyle.push({
	          value: element.style.paddingRight,
	          property: 'padding-right',
	          el: element
	        });
	        element.style.paddingRight = `${getPaddingRight(element) + scrollbarSize}px`;
	      });
	    }
	    let scrollContainer;
	    if (container.parentNode instanceof DocumentFragment) {
	      scrollContainer = ownerDocument(container).body;
	    } else {
	      // Support html overflow-y: auto for scroll stability between pages
	      // https://css-tricks.com/snippets/css/force-vertical-scrollbar/
	      const parent = container.parentElement;
	      const containerWindow = ownerWindow(container);
	      scrollContainer = (parent == null ? void 0 : parent.nodeName) === 'HTML' && containerWindow.getComputedStyle(parent).overflowY === 'scroll' ? parent : container;
	    }

	    // Block the scroll even if no scrollbar is visible to account for mobile keyboard
	    // screensize shrink.
	    restoreStyle.push({
	      value: scrollContainer.style.overflow,
	      property: 'overflow',
	      el: scrollContainer
	    }, {
	      value: scrollContainer.style.overflowX,
	      property: 'overflow-x',
	      el: scrollContainer
	    }, {
	      value: scrollContainer.style.overflowY,
	      property: 'overflow-y',
	      el: scrollContainer
	    });
	    scrollContainer.style.overflow = 'hidden';
	  }
	  const restore = () => {
	    restoreStyle.forEach(({
	      value,
	      el,
	      property
	    }) => {
	      if (value) {
	        el.style.setProperty(property, value);
	      } else {
	        el.style.removeProperty(property);
	      }
	    });
	  };
	  return restore;
	}
	function getHiddenSiblings(container) {
	  const hiddenSiblings = [];
	  [].forEach.call(container.children, element => {
	    if (element.getAttribute('aria-hidden') === 'true') {
	      hiddenSiblings.push(element);
	    }
	  });
	  return hiddenSiblings;
	}
	/**
	 * @ignore - do not document.
	 *
	 * Proper state management for containers and the modals in those containers.
	 * Simplified, but inspired by react-overlay's ModalManager class.
	 * Used by the Modal to ensure proper styling of containers.
	 */
	class ModalManager {
	  constructor() {
	    this.containers = void 0;
	    this.modals = void 0;
	    this.modals = [];
	    this.containers = [];
	  }
	  add(modal, container) {
	    let modalIndex = this.modals.indexOf(modal);
	    if (modalIndex !== -1) {
	      return modalIndex;
	    }
	    modalIndex = this.modals.length;
	    this.modals.push(modal);

	    // If the modal we are adding is already in the DOM.
	    if (modal.modalRef) {
	      ariaHidden(modal.modalRef, false);
	    }
	    const hiddenSiblings = getHiddenSiblings(container);
	    ariaHiddenSiblings(container, modal.mount, modal.modalRef, hiddenSiblings, true);
	    const containerIndex = findIndexOf(this.containers, item => item.container === container);
	    if (containerIndex !== -1) {
	      this.containers[containerIndex].modals.push(modal);
	      return modalIndex;
	    }
	    this.containers.push({
	      modals: [modal],
	      container,
	      restore: null,
	      hiddenSiblings
	    });
	    return modalIndex;
	  }
	  mount(modal, props) {
	    const containerIndex = findIndexOf(this.containers, item => item.modals.indexOf(modal) !== -1);
	    const containerInfo = this.containers[containerIndex];
	    if (!containerInfo.restore) {
	      containerInfo.restore = handleContainer(containerInfo, props);
	    }
	  }
	  remove(modal, ariaHiddenState = true) {
	    const modalIndex = this.modals.indexOf(modal);
	    if (modalIndex === -1) {
	      return modalIndex;
	    }
	    const containerIndex = findIndexOf(this.containers, item => item.modals.indexOf(modal) !== -1);
	    const containerInfo = this.containers[containerIndex];
	    containerInfo.modals.splice(containerInfo.modals.indexOf(modal), 1);
	    this.modals.splice(modalIndex, 1);

	    // If that was the last modal in a container, clean up the container.
	    if (containerInfo.modals.length === 0) {
	      // The modal might be closed before it had the chance to be mounted in the DOM.
	      if (containerInfo.restore) {
	        containerInfo.restore();
	      }
	      if (modal.modalRef) {
	        // In case the modal wasn't in the DOM yet.
	        ariaHidden(modal.modalRef, ariaHiddenState);
	      }
	      ariaHiddenSiblings(containerInfo.container, modal.mount, modal.modalRef, containerInfo.hiddenSiblings, false);
	      this.containers.splice(containerIndex, 1);
	    } else {
	      // Otherwise make sure the next top modal is visible to a screen reader.
	      const nextTop = containerInfo.modals[containerInfo.modals.length - 1];
	      // as soon as a modal is adding its modalRef is undefined. it can't set
	      // aria-hidden because the dom element doesn't exist either
	      // when modal was unmounted before modalRef gets null
	      if (nextTop.modalRef) {
	        ariaHidden(nextTop.modalRef, false);
	      }
	    }
	    return modalIndex;
	  }
	  isTopModal(modal) {
	    return this.modals.length > 0 && this.modals[this.modals.length - 1] === modal;
	  }
	}

	function getContainer(container) {
	  return typeof container === 'function' ? container() : container;
	}
	function getHasTransition(children) {
	  return children ? children.props.hasOwnProperty('in') : false;
	}

	// A modal manager used to track and manage the state of open Modals.
	// Modals don't open on the server so this won't conflict with concurrent requests.
	const defaultManager = new ModalManager();
	/**
	 *
	 * Demos:
	 *
	 * - [Modal](https://mui.com/base-ui/react-modal/#hook)
	 *
	 * API:
	 *
	 * - [useModal API](https://mui.com/base-ui/react-modal/hooks-api/#use-modal)
	 */
	function useModal(parameters) {
	  const {
	    container,
	    disableEscapeKeyDown = false,
	    disableScrollLock = false,
	    // @ts-ignore internal logic - Base UI supports the manager as a prop too
	    manager = defaultManager,
	    closeAfterTransition = false,
	    onTransitionEnter,
	    onTransitionExited,
	    children,
	    onClose,
	    open,
	    rootRef
	  } = parameters;

	  // @ts-ignore internal logic
	  const modal = reactExports.useRef({});
	  const mountNodeRef = reactExports.useRef(null);
	  const modalRef = reactExports.useRef(null);
	  const handleRef = useForkRef(modalRef, rootRef);
	  const [exited, setExited] = reactExports.useState(!open);
	  const hasTransition = getHasTransition(children);
	  let ariaHiddenProp = true;
	  if (parameters['aria-hidden'] === 'false' || parameters['aria-hidden'] === false) {
	    ariaHiddenProp = false;
	  }
	  const getDoc = () => ownerDocument(mountNodeRef.current);
	  const getModal = () => {
	    modal.current.modalRef = modalRef.current;
	    modal.current.mount = mountNodeRef.current;
	    return modal.current;
	  };
	  const handleMounted = () => {
	    manager.mount(getModal(), {
	      disableScrollLock
	    });

	    // Fix a bug on Chrome where the scroll isn't initially 0.
	    if (modalRef.current) {
	      modalRef.current.scrollTop = 0;
	    }
	  };
	  const handleOpen = useEventCallback(() => {
	    const resolvedContainer = getContainer(container) || getDoc().body;
	    manager.add(getModal(), resolvedContainer);

	    // The element was already mounted.
	    if (modalRef.current) {
	      handleMounted();
	    }
	  });
	  const isTopModal = reactExports.useCallback(() => manager.isTopModal(getModal()), [manager]);
	  const handlePortalRef = useEventCallback(node => {
	    mountNodeRef.current = node;
	    if (!node) {
	      return;
	    }
	    if (open && isTopModal()) {
	      handleMounted();
	    } else if (modalRef.current) {
	      ariaHidden(modalRef.current, ariaHiddenProp);
	    }
	  });
	  const handleClose = reactExports.useCallback(() => {
	    manager.remove(getModal(), ariaHiddenProp);
	  }, [ariaHiddenProp, manager]);
	  reactExports.useEffect(() => {
	    return () => {
	      handleClose();
	    };
	  }, [handleClose]);
	  reactExports.useEffect(() => {
	    if (open) {
	      handleOpen();
	    } else if (!hasTransition || !closeAfterTransition) {
	      handleClose();
	    }
	  }, [open, handleClose, hasTransition, closeAfterTransition, handleOpen]);
	  const createHandleKeyDown = otherHandlers => event => {
	    var _otherHandlers$onKeyD;
	    (_otherHandlers$onKeyD = otherHandlers.onKeyDown) == null || _otherHandlers$onKeyD.call(otherHandlers, event);

	    // The handler doesn't take event.defaultPrevented into account:
	    //
	    // event.preventDefault() is meant to stop default behaviors like
	    // clicking a checkbox to check it, hitting a button to submit a form,
	    // and hitting left arrow to move the cursor in a text input etc.
	    // Only special HTML elements have these default behaviors.
	    if (event.key !== 'Escape' || event.which === 229 ||
	    // Wait until IME is settled.
	    !isTopModal()) {
	      return;
	    }
	    if (!disableEscapeKeyDown) {
	      // Swallow the event, in case someone is listening for the escape key on the body.
	      event.stopPropagation();
	      if (onClose) {
	        onClose(event, 'escapeKeyDown');
	      }
	    }
	  };
	  const createHandleBackdropClick = otherHandlers => event => {
	    var _otherHandlers$onClic;
	    (_otherHandlers$onClic = otherHandlers.onClick) == null || _otherHandlers$onClic.call(otherHandlers, event);
	    if (event.target !== event.currentTarget) {
	      return;
	    }
	    if (onClose) {
	      onClose(event, 'backdropClick');
	    }
	  };
	  const getRootProps = (otherHandlers = {}) => {
	    const propsEventHandlers = extractEventHandlers(parameters);

	    // The custom event handlers shouldn't be spread on the root element
	    delete propsEventHandlers.onTransitionEnter;
	    delete propsEventHandlers.onTransitionExited;
	    const externalEventHandlers = _extends$1({}, propsEventHandlers, otherHandlers);
	    return _extends$1({
	      role: 'presentation'
	    }, externalEventHandlers, {
	      onKeyDown: createHandleKeyDown(externalEventHandlers),
	      ref: handleRef
	    });
	  };
	  const getBackdropProps = (otherHandlers = {}) => {
	    const externalEventHandlers = otherHandlers;
	    return _extends$1({
	      'aria-hidden': true
	    }, externalEventHandlers, {
	      onClick: createHandleBackdropClick(externalEventHandlers),
	      open
	    });
	  };
	  const getTransitionProps = () => {
	    const handleEnter = () => {
	      setExited(false);
	      if (onTransitionEnter) {
	        onTransitionEnter();
	      }
	    };
	    const handleExited = () => {
	      setExited(true);
	      if (onTransitionExited) {
	        onTransitionExited();
	      }
	      if (closeAfterTransition) {
	        handleClose();
	      }
	    };
	    return {
	      onEnter: createChainedFunction(handleEnter, children == null ? void 0 : children.props.onEnter),
	      onExited: createChainedFunction(handleExited, children == null ? void 0 : children.props.onExited)
	    };
	  };
	  return {
	    getRootProps,
	    getBackdropProps,
	    getTransitionProps,
	    rootRef: handleRef,
	    portalRef: handlePortalRef,
	    isTopModal,
	    exited,
	    hasTransition
	  };
	}

	var CancelIcon = createSvgIcon(/*#__PURE__*/jsxRuntimeExports.jsx("path", {
	  d: "M12 2C6.47 2 2 6.47 2 12s4.47 10 10 10 10-4.47 10-10S17.53 2 12 2zm5 13.59L15.59 17 12 13.41 8.41 17 7 15.59 10.59 12 7 8.41 8.41 7 12 10.59 15.59 7 17 8.41 13.41 12 17 15.59z"
	}), 'Cancel');

	function getChipUtilityClass(slot) {
	  return generateUtilityClass('MuiChip', slot);
	}
	const chipClasses = generateUtilityClasses('MuiChip', ['root', 'sizeSmall', 'sizeMedium', 'colorError', 'colorInfo', 'colorPrimary', 'colorSecondary', 'colorSuccess', 'colorWarning', 'disabled', 'clickable', 'clickableColorPrimary', 'clickableColorSecondary', 'deletable', 'deletableColorPrimary', 'deletableColorSecondary', 'outlined', 'filled', 'outlinedPrimary', 'outlinedSecondary', 'filledPrimary', 'filledSecondary', 'avatar', 'avatarSmall', 'avatarMedium', 'avatarColorPrimary', 'avatarColorSecondary', 'icon', 'iconSmall', 'iconMedium', 'iconColorPrimary', 'iconColorSecondary', 'label', 'labelSmall', 'labelMedium', 'deleteIcon', 'deleteIconSmall', 'deleteIconMedium', 'deleteIconColorPrimary', 'deleteIconColorSecondary', 'deleteIconOutlinedColorPrimary', 'deleteIconOutlinedColorSecondary', 'deleteIconFilledColorPrimary', 'deleteIconFilledColorSecondary', 'focusVisible']);
	var chipClasses$1 = chipClasses;

	const _excluded$g = ["avatar", "className", "clickable", "color", "component", "deleteIcon", "disabled", "icon", "label", "onClick", "onDelete", "onKeyDown", "onKeyUp", "size", "variant", "tabIndex", "skipFocusWhenDisabled"];
	const useUtilityClasses$c = ownerState => {
	  const {
	    classes,
	    disabled,
	    size,
	    color,
	    iconColor,
	    onDelete,
	    clickable,
	    variant
	  } = ownerState;
	  const slots = {
	    root: ['root', variant, disabled && 'disabled', `size${capitalize$2(size)}`, `color${capitalize$2(color)}`, clickable && 'clickable', clickable && `clickableColor${capitalize$2(color)}`, onDelete && 'deletable', onDelete && `deletableColor${capitalize$2(color)}`, `${variant}${capitalize$2(color)}`],
	    label: ['label', `label${capitalize$2(size)}`],
	    avatar: ['avatar', `avatar${capitalize$2(size)}`, `avatarColor${capitalize$2(color)}`],
	    icon: ['icon', `icon${capitalize$2(size)}`, `iconColor${capitalize$2(iconColor)}`],
	    deleteIcon: ['deleteIcon', `deleteIcon${capitalize$2(size)}`, `deleteIconColor${capitalize$2(color)}`, `deleteIcon${capitalize$2(variant)}Color${capitalize$2(color)}`]
	  };
	  return composeClasses(slots, getChipUtilityClass, classes);
	};
	const ChipRoot = styled$1('div', {
	  name: 'MuiChip',
	  slot: 'Root',
	  overridesResolver: (props, styles) => {
	    const {
	      ownerState
	    } = props;
	    const {
	      color,
	      iconColor,
	      clickable,
	      onDelete,
	      size,
	      variant
	    } = ownerState;
	    return [{
	      [`& .${chipClasses$1.avatar}`]: styles.avatar
	    }, {
	      [`& .${chipClasses$1.avatar}`]: styles[`avatar${capitalize$2(size)}`]
	    }, {
	      [`& .${chipClasses$1.avatar}`]: styles[`avatarColor${capitalize$2(color)}`]
	    }, {
	      [`& .${chipClasses$1.icon}`]: styles.icon
	    }, {
	      [`& .${chipClasses$1.icon}`]: styles[`icon${capitalize$2(size)}`]
	    }, {
	      [`& .${chipClasses$1.icon}`]: styles[`iconColor${capitalize$2(iconColor)}`]
	    }, {
	      [`& .${chipClasses$1.deleteIcon}`]: styles.deleteIcon
	    }, {
	      [`& .${chipClasses$1.deleteIcon}`]: styles[`deleteIcon${capitalize$2(size)}`]
	    }, {
	      [`& .${chipClasses$1.deleteIcon}`]: styles[`deleteIconColor${capitalize$2(color)}`]
	    }, {
	      [`& .${chipClasses$1.deleteIcon}`]: styles[`deleteIcon${capitalize$2(variant)}Color${capitalize$2(color)}`]
	    }, styles.root, styles[`size${capitalize$2(size)}`], styles[`color${capitalize$2(color)}`], clickable && styles.clickable, clickable && color !== 'default' && styles[`clickableColor${capitalize$2(color)})`], onDelete && styles.deletable, onDelete && color !== 'default' && styles[`deletableColor${capitalize$2(color)}`], styles[variant], styles[`${variant}${capitalize$2(color)}`]];
	  }
	})(({
	  theme,
	  ownerState
	}) => {
	  const textColor = theme.palette.mode === 'light' ? theme.palette.grey[700] : theme.palette.grey[300];
	  return _extends$1({
	    maxWidth: '100%',
	    fontFamily: theme.typography.fontFamily,
	    fontSize: theme.typography.pxToRem(13),
	    display: 'inline-flex',
	    alignItems: 'center',
	    justifyContent: 'center',
	    height: 32,
	    color: (theme.vars || theme).palette.text.primary,
	    backgroundColor: (theme.vars || theme).palette.action.selected,
	    borderRadius: 32 / 2,
	    whiteSpace: 'nowrap',
	    transition: theme.transitions.create(['background-color', 'box-shadow']),
	    // reset cursor explicitly in case ButtonBase is used
	    cursor: 'unset',
	    // We disable the focus ring for mouse, touch and keyboard users.
	    outline: 0,
	    textDecoration: 'none',
	    border: 0,
	    // Remove `button` border
	    padding: 0,
	    // Remove `button` padding
	    verticalAlign: 'middle',
	    boxSizing: 'border-box',
	    [`&.${chipClasses$1.disabled}`]: {
	      opacity: (theme.vars || theme).palette.action.disabledOpacity,
	      pointerEvents: 'none'
	    },
	    [`& .${chipClasses$1.avatar}`]: {
	      marginLeft: 5,
	      marginRight: -6,
	      width: 24,
	      height: 24,
	      color: theme.vars ? theme.vars.palette.Chip.defaultAvatarColor : textColor,
	      fontSize: theme.typography.pxToRem(12)
	    },
	    [`& .${chipClasses$1.avatarColorPrimary}`]: {
	      color: (theme.vars || theme).palette.primary.contrastText,
	      backgroundColor: (theme.vars || theme).palette.primary.dark
	    },
	    [`& .${chipClasses$1.avatarColorSecondary}`]: {
	      color: (theme.vars || theme).palette.secondary.contrastText,
	      backgroundColor: (theme.vars || theme).palette.secondary.dark
	    },
	    [`& .${chipClasses$1.avatarSmall}`]: {
	      marginLeft: 4,
	      marginRight: -4,
	      width: 18,
	      height: 18,
	      fontSize: theme.typography.pxToRem(10)
	    },
	    [`& .${chipClasses$1.icon}`]: _extends$1({
	      marginLeft: 5,
	      marginRight: -6
	    }, ownerState.size === 'small' && {
	      fontSize: 18,
	      marginLeft: 4,
	      marginRight: -4
	    }, ownerState.iconColor === ownerState.color && _extends$1({
	      color: theme.vars ? theme.vars.palette.Chip.defaultIconColor : textColor
	    }, ownerState.color !== 'default' && {
	      color: 'inherit'
	    })),
	    [`& .${chipClasses$1.deleteIcon}`]: _extends$1({
	      WebkitTapHighlightColor: 'transparent',
	      color: theme.vars ? `rgba(${theme.vars.palette.text.primaryChannel} / 0.26)` : colorManipulatorExports.alpha(theme.palette.text.primary, 0.26),
	      fontSize: 22,
	      cursor: 'pointer',
	      margin: '0 5px 0 -6px',
	      '&:hover': {
	        color: theme.vars ? `rgba(${theme.vars.palette.text.primaryChannel} / 0.4)` : colorManipulatorExports.alpha(theme.palette.text.primary, 0.4)
	      }
	    }, ownerState.size === 'small' && {
	      fontSize: 16,
	      marginRight: 4,
	      marginLeft: -4
	    }, ownerState.color !== 'default' && {
	      color: theme.vars ? `rgba(${theme.vars.palette[ownerState.color].contrastTextChannel} / 0.7)` : colorManipulatorExports.alpha(theme.palette[ownerState.color].contrastText, 0.7),
	      '&:hover, &:active': {
	        color: (theme.vars || theme).palette[ownerState.color].contrastText
	      }
	    })
	  }, ownerState.size === 'small' && {
	    height: 24
	  }, ownerState.color !== 'default' && {
	    backgroundColor: (theme.vars || theme).palette[ownerState.color].main,
	    color: (theme.vars || theme).palette[ownerState.color].contrastText
	  }, ownerState.onDelete && {
	    [`&.${chipClasses$1.focusVisible}`]: {
	      backgroundColor: theme.vars ? `rgba(${theme.vars.palette.action.selectedChannel} / calc(${theme.vars.palette.action.selectedOpacity} + ${theme.vars.palette.action.focusOpacity}))` : colorManipulatorExports.alpha(theme.palette.action.selected, theme.palette.action.selectedOpacity + theme.palette.action.focusOpacity)
	    }
	  }, ownerState.onDelete && ownerState.color !== 'default' && {
	    [`&.${chipClasses$1.focusVisible}`]: {
	      backgroundColor: (theme.vars || theme).palette[ownerState.color].dark
	    }
	  });
	}, ({
	  theme,
	  ownerState
	}) => _extends$1({}, ownerState.clickable && {
	  userSelect: 'none',
	  WebkitTapHighlightColor: 'transparent',
	  cursor: 'pointer',
	  '&:hover': {
	    backgroundColor: theme.vars ? `rgba(${theme.vars.palette.action.selectedChannel} / calc(${theme.vars.palette.action.selectedOpacity} + ${theme.vars.palette.action.hoverOpacity}))` : colorManipulatorExports.alpha(theme.palette.action.selected, theme.palette.action.selectedOpacity + theme.palette.action.hoverOpacity)
	  },
	  [`&.${chipClasses$1.focusVisible}`]: {
	    backgroundColor: theme.vars ? `rgba(${theme.vars.palette.action.selectedChannel} / calc(${theme.vars.palette.action.selectedOpacity} + ${theme.vars.palette.action.focusOpacity}))` : colorManipulatorExports.alpha(theme.palette.action.selected, theme.palette.action.selectedOpacity + theme.palette.action.focusOpacity)
	  },
	  '&:active': {
	    boxShadow: (theme.vars || theme).shadows[1]
	  }
	}, ownerState.clickable && ownerState.color !== 'default' && {
	  [`&:hover, &.${chipClasses$1.focusVisible}`]: {
	    backgroundColor: (theme.vars || theme).palette[ownerState.color].dark
	  }
	}), ({
	  theme,
	  ownerState
	}) => _extends$1({}, ownerState.variant === 'outlined' && {
	  backgroundColor: 'transparent',
	  border: theme.vars ? `1px solid ${theme.vars.palette.Chip.defaultBorder}` : `1px solid ${theme.palette.mode === 'light' ? theme.palette.grey[400] : theme.palette.grey[700]}`,
	  [`&.${chipClasses$1.clickable}:hover`]: {
	    backgroundColor: (theme.vars || theme).palette.action.hover
	  },
	  [`&.${chipClasses$1.focusVisible}`]: {
	    backgroundColor: (theme.vars || theme).palette.action.focus
	  },
	  [`& .${chipClasses$1.avatar}`]: {
	    marginLeft: 4
	  },
	  [`& .${chipClasses$1.avatarSmall}`]: {
	    marginLeft: 2
	  },
	  [`& .${chipClasses$1.icon}`]: {
	    marginLeft: 4
	  },
	  [`& .${chipClasses$1.iconSmall}`]: {
	    marginLeft: 2
	  },
	  [`& .${chipClasses$1.deleteIcon}`]: {
	    marginRight: 5
	  },
	  [`& .${chipClasses$1.deleteIconSmall}`]: {
	    marginRight: 3
	  }
	}, ownerState.variant === 'outlined' && ownerState.color !== 'default' && {
	  color: (theme.vars || theme).palette[ownerState.color].main,
	  border: `1px solid ${theme.vars ? `rgba(${theme.vars.palette[ownerState.color].mainChannel} / 0.7)` : colorManipulatorExports.alpha(theme.palette[ownerState.color].main, 0.7)}`,
	  [`&.${chipClasses$1.clickable}:hover`]: {
	    backgroundColor: theme.vars ? `rgba(${theme.vars.palette[ownerState.color].mainChannel} / ${theme.vars.palette.action.hoverOpacity})` : colorManipulatorExports.alpha(theme.palette[ownerState.color].main, theme.palette.action.hoverOpacity)
	  },
	  [`&.${chipClasses$1.focusVisible}`]: {
	    backgroundColor: theme.vars ? `rgba(${theme.vars.palette[ownerState.color].mainChannel} / ${theme.vars.palette.action.focusOpacity})` : colorManipulatorExports.alpha(theme.palette[ownerState.color].main, theme.palette.action.focusOpacity)
	  },
	  [`& .${chipClasses$1.deleteIcon}`]: {
	    color: theme.vars ? `rgba(${theme.vars.palette[ownerState.color].mainChannel} / 0.7)` : colorManipulatorExports.alpha(theme.palette[ownerState.color].main, 0.7),
	    '&:hover, &:active': {
	      color: (theme.vars || theme).palette[ownerState.color].main
	    }
	  }
	}));
	const ChipLabel = styled$1('span', {
	  name: 'MuiChip',
	  slot: 'Label',
	  overridesResolver: (props, styles) => {
	    const {
	      ownerState
	    } = props;
	    const {
	      size
	    } = ownerState;
	    return [styles.label, styles[`label${capitalize$2(size)}`]];
	  }
	})(({
	  ownerState
	}) => _extends$1({
	  overflow: 'hidden',
	  textOverflow: 'ellipsis',
	  paddingLeft: 12,
	  paddingRight: 12,
	  whiteSpace: 'nowrap'
	}, ownerState.variant === 'outlined' && {
	  paddingLeft: 11,
	  paddingRight: 11
	}, ownerState.size === 'small' && {
	  paddingLeft: 8,
	  paddingRight: 8
	}, ownerState.size === 'small' && ownerState.variant === 'outlined' && {
	  paddingLeft: 7,
	  paddingRight: 7
	}));
	function isDeleteKeyboardEvent(keyboardEvent) {
	  return keyboardEvent.key === 'Backspace' || keyboardEvent.key === 'Delete';
	}

	/**
	 * Chips represent complex entities in small blocks, such as a contact.
	 */
	const Chip = /*#__PURE__*/reactExports.forwardRef(function Chip(inProps, ref) {
	  const props = useThemeProps({
	    props: inProps,
	    name: 'MuiChip'
	  });
	  const {
	      avatar: avatarProp,
	      className,
	      clickable: clickableProp,
	      color = 'default',
	      component: ComponentProp,
	      deleteIcon: deleteIconProp,
	      disabled = false,
	      icon: iconProp,
	      label,
	      onClick,
	      onDelete,
	      onKeyDown,
	      onKeyUp,
	      size = 'medium',
	      variant = 'filled',
	      tabIndex,
	      skipFocusWhenDisabled = false // TODO v6: Rename to `focusableWhenDisabled`.
	    } = props,
	    other = _objectWithoutPropertiesLoose(props, _excluded$g);
	  const chipRef = reactExports.useRef(null);
	  const handleRef = useForkRef(chipRef, ref);
	  const handleDeleteIconClick = event => {
	    // Stop the event from bubbling up to the `Chip`
	    event.stopPropagation();
	    if (onDelete) {
	      onDelete(event);
	    }
	  };
	  const handleKeyDown = event => {
	    // Ignore events from children of `Chip`.
	    if (event.currentTarget === event.target && isDeleteKeyboardEvent(event)) {
	      // Will be handled in keyUp, otherwise some browsers
	      // might init navigation
	      event.preventDefault();
	    }
	    if (onKeyDown) {
	      onKeyDown(event);
	    }
	  };
	  const handleKeyUp = event => {
	    // Ignore events from children of `Chip`.
	    if (event.currentTarget === event.target) {
	      if (onDelete && isDeleteKeyboardEvent(event)) {
	        onDelete(event);
	      } else if (event.key === 'Escape' && chipRef.current) {
	        chipRef.current.blur();
	      }
	    }
	    if (onKeyUp) {
	      onKeyUp(event);
	    }
	  };
	  const clickable = clickableProp !== false && onClick ? true : clickableProp;
	  const component = clickable || onDelete ? ButtonBase$1 : ComponentProp || 'div';
	  const ownerState = _extends$1({}, props, {
	    component,
	    disabled,
	    size,
	    color,
	    iconColor: /*#__PURE__*/ /*#__PURE__*/reactExports.isValidElement(iconProp) ? iconProp.props.color || color : color,
	    onDelete: !!onDelete,
	    clickable,
	    variant
	  });
	  const classes = useUtilityClasses$c(ownerState);
	  const moreProps = component === ButtonBase$1 ? _extends$1({
	    component: ComponentProp || 'div',
	    focusVisibleClassName: classes.focusVisible
	  }, onDelete && {
	    disableRipple: true
	  }) : {};
	  let deleteIcon = null;
	  if (onDelete) {
	    deleteIcon = deleteIconProp && /*#__PURE__*/reactExports.isValidElement(deleteIconProp) ? (/*#__PURE__*/reactExports.cloneElement(deleteIconProp, {
	      className: clsx(deleteIconProp.props.className, classes.deleteIcon),
	      onClick: handleDeleteIconClick
	    })) : /*#__PURE__*/jsxRuntimeExports.jsx(CancelIcon, {
	      className: clsx(classes.deleteIcon),
	      onClick: handleDeleteIconClick
	    });
	  }
	  let avatar = null;
	  if (avatarProp && /*#__PURE__*/reactExports.isValidElement(avatarProp)) {
	    avatar = /*#__PURE__*/reactExports.cloneElement(avatarProp, {
	      className: clsx(classes.avatar, avatarProp.props.className)
	    });
	  }
	  let icon = null;
	  if (iconProp && /*#__PURE__*/reactExports.isValidElement(iconProp)) {
	    icon = /*#__PURE__*/reactExports.cloneElement(iconProp, {
	      className: clsx(classes.icon, iconProp.props.className)
	    });
	  }
	  return /*#__PURE__*/jsxRuntimeExports.jsxs(ChipRoot, _extends$1({
	    as: component,
	    className: clsx(classes.root, className),
	    disabled: clickable && disabled ? true : undefined,
	    onClick: onClick,
	    onKeyDown: handleKeyDown,
	    onKeyUp: handleKeyUp,
	    ref: handleRef,
	    tabIndex: skipFocusWhenDisabled && disabled ? -1 : tabIndex,
	    ownerState: ownerState
	  }, moreProps, other, {
	    children: [avatar || icon, /*#__PURE__*/jsxRuntimeExports.jsx(ChipLabel, {
	      className: clsx(classes.label),
	      ownerState: ownerState,
	      children: label
	    }), deleteIcon]
	  }));
	});
	var Chip$1 = Chip;

	const _excluded$f = ["addEndListener", "appear", "children", "easing", "in", "onEnter", "onEntered", "onEntering", "onExit", "onExited", "onExiting", "style", "timeout", "TransitionComponent"];
	const styles$1 = {
	  entering: {
	    opacity: 1
	  },
	  entered: {
	    opacity: 1
	  }
	};

	/**
	 * The Fade transition is used by the [Modal](/material-ui/react-modal/) component.
	 * It uses [react-transition-group](https://github.com/reactjs/react-transition-group) internally.
	 */
	const Fade = /*#__PURE__*/reactExports.forwardRef(function Fade(props, ref) {
	  const theme = useTheme();
	  const defaultTimeout = {
	    enter: theme.transitions.duration.enteringScreen,
	    exit: theme.transitions.duration.leavingScreen
	  };
	  const {
	      addEndListener,
	      appear = true,
	      children,
	      easing,
	      in: inProp,
	      onEnter,
	      onEntered,
	      onEntering,
	      onExit,
	      onExited,
	      onExiting,
	      style,
	      timeout = defaultTimeout,
	      // eslint-disable-next-line react/prop-types
	      TransitionComponent = Transition$1
	    } = props,
	    other = _objectWithoutPropertiesLoose(props, _excluded$f);
	  const nodeRef = reactExports.useRef(null);
	  const handleRef = useForkRef(nodeRef, children.ref, ref);
	  const normalizedTransitionCallback = callback => maybeIsAppearing => {
	    if (callback) {
	      const node = nodeRef.current;

	      // onEnterXxx and onExitXxx callbacks have a different arguments.length value.
	      if (maybeIsAppearing === undefined) {
	        callback(node);
	      } else {
	        callback(node, maybeIsAppearing);
	      }
	    }
	  };
	  const handleEntering = normalizedTransitionCallback(onEntering);
	  const handleEnter = normalizedTransitionCallback((node, isAppearing) => {
	    reflow(node); // So the animation always start from the start.

	    const transitionProps = getTransitionProps({
	      style,
	      timeout,
	      easing
	    }, {
	      mode: 'enter'
	    });
	    node.style.webkitTransition = theme.transitions.create('opacity', transitionProps);
	    node.style.transition = theme.transitions.create('opacity', transitionProps);
	    if (onEnter) {
	      onEnter(node, isAppearing);
	    }
	  });
	  const handleEntered = normalizedTransitionCallback(onEntered);
	  const handleExiting = normalizedTransitionCallback(onExiting);
	  const handleExit = normalizedTransitionCallback(node => {
	    const transitionProps = getTransitionProps({
	      style,
	      timeout,
	      easing
	    }, {
	      mode: 'exit'
	    });
	    node.style.webkitTransition = theme.transitions.create('opacity', transitionProps);
	    node.style.transition = theme.transitions.create('opacity', transitionProps);
	    if (onExit) {
	      onExit(node);
	    }
	  });
	  const handleExited = normalizedTransitionCallback(onExited);
	  const handleAddEndListener = next => {
	    if (addEndListener) {
	      // Old call signature before `react-transition-group` implemented `nodeRef`
	      addEndListener(nodeRef.current, next);
	    }
	  };
	  return /*#__PURE__*/jsxRuntimeExports.jsx(TransitionComponent, _extends$1({
	    appear: appear,
	    in: inProp,
	    nodeRef: nodeRef ,
	    onEnter: handleEnter,
	    onEntered: handleEntered,
	    onEntering: handleEntering,
	    onExit: handleExit,
	    onExited: handleExited,
	    onExiting: handleExiting,
	    addEndListener: handleAddEndListener,
	    timeout: timeout
	  }, other, {
	    children: (state, childProps) => {
	      return /*#__PURE__*/reactExports.cloneElement(children, _extends$1({
	        style: _extends$1({
	          opacity: 0,
	          visibility: state === 'exited' && !inProp ? 'hidden' : undefined
	        }, styles$1[state], style, children.props.style),
	        ref: handleRef
	      }, childProps));
	    }
	  }));
	});
	var Fade$1 = Fade;

	function getBackdropUtilityClass(slot) {
	  return generateUtilityClass('MuiBackdrop', slot);
	}
	generateUtilityClasses('MuiBackdrop', ['root', 'invisible']);

	const _excluded$e = ["children", "className", "component", "components", "componentsProps", "invisible", "open", "slotProps", "slots", "TransitionComponent", "transitionDuration"];
	const useUtilityClasses$b = ownerState => {
	  const {
	    classes,
	    invisible
	  } = ownerState;
	  const slots = {
	    root: ['root', invisible && 'invisible']
	  };
	  return composeClasses(slots, getBackdropUtilityClass, classes);
	};
	const BackdropRoot = styled$1('div', {
	  name: 'MuiBackdrop',
	  slot: 'Root',
	  overridesResolver: (props, styles) => {
	    const {
	      ownerState
	    } = props;
	    return [styles.root, ownerState.invisible && styles.invisible];
	  }
	})(({
	  ownerState
	}) => _extends$1({
	  position: 'fixed',
	  display: 'flex',
	  alignItems: 'center',
	  justifyContent: 'center',
	  right: 0,
	  bottom: 0,
	  top: 0,
	  left: 0,
	  backgroundColor: 'rgba(0, 0, 0, 0.5)',
	  WebkitTapHighlightColor: 'transparent'
	}, ownerState.invisible && {
	  backgroundColor: 'transparent'
	}));
	const Backdrop = /*#__PURE__*/reactExports.forwardRef(function Backdrop(inProps, ref) {
	  var _slotProps$root, _ref, _slots$root;
	  const props = useThemeProps({
	    props: inProps,
	    name: 'MuiBackdrop'
	  });
	  const {
	      children,
	      className,
	      component = 'div',
	      components = {},
	      componentsProps = {},
	      invisible = false,
	      open,
	      slotProps = {},
	      slots = {},
	      TransitionComponent = Fade$1,
	      transitionDuration
	    } = props,
	    other = _objectWithoutPropertiesLoose(props, _excluded$e);
	  const ownerState = _extends$1({}, props, {
	    component,
	    invisible
	  });
	  const classes = useUtilityClasses$b(ownerState);
	  const rootSlotProps = (_slotProps$root = slotProps.root) != null ? _slotProps$root : componentsProps.root;
	  return /*#__PURE__*/jsxRuntimeExports.jsx(TransitionComponent, _extends$1({
	    in: open,
	    timeout: transitionDuration
	  }, other, {
	    children: /*#__PURE__*/jsxRuntimeExports.jsx(BackdropRoot, _extends$1({
	      "aria-hidden": true
	    }, rootSlotProps, {
	      as: (_ref = (_slots$root = slots.root) != null ? _slots$root : components.Root) != null ? _ref : component,
	      className: clsx(classes.root, className, rootSlotProps == null ? void 0 : rootSlotProps.className),
	      ownerState: _extends$1({}, ownerState, rootSlotProps == null ? void 0 : rootSlotProps.ownerState),
	      classes: classes,
	      ref: ref,
	      children: children
	    }))
	  }));
	});
	var Backdrop$1 = Backdrop;

	function getButtonUtilityClass(slot) {
	  return generateUtilityClass('MuiButton', slot);
	}
	const buttonClasses = generateUtilityClasses('MuiButton', ['root', 'text', 'textInherit', 'textPrimary', 'textSecondary', 'textSuccess', 'textError', 'textInfo', 'textWarning', 'outlined', 'outlinedInherit', 'outlinedPrimary', 'outlinedSecondary', 'outlinedSuccess', 'outlinedError', 'outlinedInfo', 'outlinedWarning', 'contained', 'containedInherit', 'containedPrimary', 'containedSecondary', 'containedSuccess', 'containedError', 'containedInfo', 'containedWarning', 'disableElevation', 'focusVisible', 'disabled', 'colorInherit', 'colorPrimary', 'colorSecondary', 'colorSuccess', 'colorError', 'colorInfo', 'colorWarning', 'textSizeSmall', 'textSizeMedium', 'textSizeLarge', 'outlinedSizeSmall', 'outlinedSizeMedium', 'outlinedSizeLarge', 'containedSizeSmall', 'containedSizeMedium', 'containedSizeLarge', 'sizeMedium', 'sizeSmall', 'sizeLarge', 'fullWidth', 'startIcon', 'endIcon', 'icon', 'iconSizeSmall', 'iconSizeMedium', 'iconSizeLarge']);
	var buttonClasses$1 = buttonClasses;

	/**
	 * @ignore - internal component.
	 */
	const ButtonGroupContext = /*#__PURE__*/reactExports.createContext({});
	var ButtonGroupContext$1 = ButtonGroupContext;

	/**
	 * @ignore - internal component.
	 */
	const ButtonGroupButtonContext = /*#__PURE__*/reactExports.createContext(undefined);
	var ButtonGroupButtonContext$1 = ButtonGroupButtonContext;

	const _excluded$d = ["children", "color", "component", "className", "disabled", "disableElevation", "disableFocusRipple", "endIcon", "focusVisibleClassName", "fullWidth", "size", "startIcon", "type", "variant"];
	const useUtilityClasses$a = ownerState => {
	  const {
	    color,
	    disableElevation,
	    fullWidth,
	    size,
	    variant,
	    classes
	  } = ownerState;
	  const slots = {
	    root: ['root', variant, `${variant}${capitalize$2(color)}`, `size${capitalize$2(size)}`, `${variant}Size${capitalize$2(size)}`, `color${capitalize$2(color)}`, disableElevation && 'disableElevation', fullWidth && 'fullWidth'],
	    label: ['label'],
	    startIcon: ['icon', 'startIcon', `iconSize${capitalize$2(size)}`],
	    endIcon: ['icon', 'endIcon', `iconSize${capitalize$2(size)}`]
	  };
	  const composedClasses = composeClasses(slots, getButtonUtilityClass, classes);
	  return _extends$1({}, classes, composedClasses);
	};
	const commonIconStyles = ownerState => _extends$1({}, ownerState.size === 'small' && {
	  '& > *:nth-of-type(1)': {
	    fontSize: 18
	  }
	}, ownerState.size === 'medium' && {
	  '& > *:nth-of-type(1)': {
	    fontSize: 20
	  }
	}, ownerState.size === 'large' && {
	  '& > *:nth-of-type(1)': {
	    fontSize: 22
	  }
	});
	const ButtonRoot = styled$1(ButtonBase$1, {
	  shouldForwardProp: prop => rootShouldForwardProp$1(prop) || prop === 'classes',
	  name: 'MuiButton',
	  slot: 'Root',
	  overridesResolver: (props, styles) => {
	    const {
	      ownerState
	    } = props;
	    return [styles.root, styles[ownerState.variant], styles[`${ownerState.variant}${capitalize$2(ownerState.color)}`], styles[`size${capitalize$2(ownerState.size)}`], styles[`${ownerState.variant}Size${capitalize$2(ownerState.size)}`], ownerState.color === 'inherit' && styles.colorInherit, ownerState.disableElevation && styles.disableElevation, ownerState.fullWidth && styles.fullWidth];
	  }
	})(({
	  theme,
	  ownerState
	}) => {
	  var _theme$palette$getCon, _theme$palette;
	  const inheritContainedBackgroundColor = theme.palette.mode === 'light' ? theme.palette.grey[300] : theme.palette.grey[800];
	  const inheritContainedHoverBackgroundColor = theme.palette.mode === 'light' ? theme.palette.grey.A100 : theme.palette.grey[700];
	  return _extends$1({}, theme.typography.button, {
	    minWidth: 64,
	    padding: '6px 16px',
	    borderRadius: (theme.vars || theme).shape.borderRadius,
	    transition: theme.transitions.create(['background-color', 'box-shadow', 'border-color', 'color'], {
	      duration: theme.transitions.duration.short
	    }),
	    '&:hover': _extends$1({
	      textDecoration: 'none',
	      backgroundColor: theme.vars ? `rgba(${theme.vars.palette.text.primaryChannel} / ${theme.vars.palette.action.hoverOpacity})` : colorManipulatorExports.alpha(theme.palette.text.primary, theme.palette.action.hoverOpacity),
	      // Reset on touch devices, it doesn't add specificity
	      '@media (hover: none)': {
	        backgroundColor: 'transparent'
	      }
	    }, ownerState.variant === 'text' && ownerState.color !== 'inherit' && {
	      backgroundColor: theme.vars ? `rgba(${theme.vars.palette[ownerState.color].mainChannel} / ${theme.vars.palette.action.hoverOpacity})` : colorManipulatorExports.alpha(theme.palette[ownerState.color].main, theme.palette.action.hoverOpacity),
	      // Reset on touch devices, it doesn't add specificity
	      '@media (hover: none)': {
	        backgroundColor: 'transparent'
	      }
	    }, ownerState.variant === 'outlined' && ownerState.color !== 'inherit' && {
	      border: `1px solid ${(theme.vars || theme).palette[ownerState.color].main}`,
	      backgroundColor: theme.vars ? `rgba(${theme.vars.palette[ownerState.color].mainChannel} / ${theme.vars.palette.action.hoverOpacity})` : colorManipulatorExports.alpha(theme.palette[ownerState.color].main, theme.palette.action.hoverOpacity),
	      // Reset on touch devices, it doesn't add specificity
	      '@media (hover: none)': {
	        backgroundColor: 'transparent'
	      }
	    }, ownerState.variant === 'contained' && {
	      backgroundColor: theme.vars ? theme.vars.palette.Button.inheritContainedHoverBg : inheritContainedHoverBackgroundColor,
	      boxShadow: (theme.vars || theme).shadows[4],
	      // Reset on touch devices, it doesn't add specificity
	      '@media (hover: none)': {
	        boxShadow: (theme.vars || theme).shadows[2],
	        backgroundColor: (theme.vars || theme).palette.grey[300]
	      }
	    }, ownerState.variant === 'contained' && ownerState.color !== 'inherit' && {
	      backgroundColor: (theme.vars || theme).palette[ownerState.color].dark,
	      // Reset on touch devices, it doesn't add specificity
	      '@media (hover: none)': {
	        backgroundColor: (theme.vars || theme).palette[ownerState.color].main
	      }
	    }),
	    '&:active': _extends$1({}, ownerState.variant === 'contained' && {
	      boxShadow: (theme.vars || theme).shadows[8]
	    }),
	    [`&.${buttonClasses$1.focusVisible}`]: _extends$1({}, ownerState.variant === 'contained' && {
	      boxShadow: (theme.vars || theme).shadows[6]
	    }),
	    [`&.${buttonClasses$1.disabled}`]: _extends$1({
	      color: (theme.vars || theme).palette.action.disabled
	    }, ownerState.variant === 'outlined' && {
	      border: `1px solid ${(theme.vars || theme).palette.action.disabledBackground}`
	    }, ownerState.variant === 'contained' && {
	      color: (theme.vars || theme).palette.action.disabled,
	      boxShadow: (theme.vars || theme).shadows[0],
	      backgroundColor: (theme.vars || theme).palette.action.disabledBackground
	    })
	  }, ownerState.variant === 'text' && {
	    padding: '6px 8px'
	  }, ownerState.variant === 'text' && ownerState.color !== 'inherit' && {
	    color: (theme.vars || theme).palette[ownerState.color].main
	  }, ownerState.variant === 'outlined' && {
	    padding: '5px 15px',
	    border: '1px solid currentColor'
	  }, ownerState.variant === 'outlined' && ownerState.color !== 'inherit' && {
	    color: (theme.vars || theme).palette[ownerState.color].main,
	    border: theme.vars ? `1px solid rgba(${theme.vars.palette[ownerState.color].mainChannel} / 0.5)` : `1px solid ${colorManipulatorExports.alpha(theme.palette[ownerState.color].main, 0.5)}`
	  }, ownerState.variant === 'contained' && {
	    color: theme.vars ?
	    // this is safe because grey does not change between default light/dark mode
	    theme.vars.palette.text.primary : (_theme$palette$getCon = (_theme$palette = theme.palette).getContrastText) == null ? void 0 : _theme$palette$getCon.call(_theme$palette, theme.palette.grey[300]),
	    backgroundColor: theme.vars ? theme.vars.palette.Button.inheritContainedBg : inheritContainedBackgroundColor,
	    boxShadow: (theme.vars || theme).shadows[2]
	  }, ownerState.variant === 'contained' && ownerState.color !== 'inherit' && {
	    color: (theme.vars || theme).palette[ownerState.color].contrastText,
	    backgroundColor: (theme.vars || theme).palette[ownerState.color].main
	  }, ownerState.color === 'inherit' && {
	    color: 'inherit',
	    borderColor: 'currentColor'
	  }, ownerState.size === 'small' && ownerState.variant === 'text' && {
	    padding: '4px 5px',
	    fontSize: theme.typography.pxToRem(13)
	  }, ownerState.size === 'large' && ownerState.variant === 'text' && {
	    padding: '8px 11px',
	    fontSize: theme.typography.pxToRem(15)
	  }, ownerState.size === 'small' && ownerState.variant === 'outlined' && {
	    padding: '3px 9px',
	    fontSize: theme.typography.pxToRem(13)
	  }, ownerState.size === 'large' && ownerState.variant === 'outlined' && {
	    padding: '7px 21px',
	    fontSize: theme.typography.pxToRem(15)
	  }, ownerState.size === 'small' && ownerState.variant === 'contained' && {
	    padding: '4px 10px',
	    fontSize: theme.typography.pxToRem(13)
	  }, ownerState.size === 'large' && ownerState.variant === 'contained' && {
	    padding: '8px 22px',
	    fontSize: theme.typography.pxToRem(15)
	  }, ownerState.fullWidth && {
	    width: '100%'
	  });
	}, ({
	  ownerState
	}) => ownerState.disableElevation && {
	  boxShadow: 'none',
	  '&:hover': {
	    boxShadow: 'none'
	  },
	  [`&.${buttonClasses$1.focusVisible}`]: {
	    boxShadow: 'none'
	  },
	  '&:active': {
	    boxShadow: 'none'
	  },
	  [`&.${buttonClasses$1.disabled}`]: {
	    boxShadow: 'none'
	  }
	});
	const ButtonStartIcon = styled$1('span', {
	  name: 'MuiButton',
	  slot: 'StartIcon',
	  overridesResolver: (props, styles) => {
	    const {
	      ownerState
	    } = props;
	    return [styles.startIcon, styles[`iconSize${capitalize$2(ownerState.size)}`]];
	  }
	})(({
	  ownerState
	}) => _extends$1({
	  display: 'inherit',
	  marginRight: 8,
	  marginLeft: -4
	}, ownerState.size === 'small' && {
	  marginLeft: -2
	}, commonIconStyles(ownerState)));
	const ButtonEndIcon = styled$1('span', {
	  name: 'MuiButton',
	  slot: 'EndIcon',
	  overridesResolver: (props, styles) => {
	    const {
	      ownerState
	    } = props;
	    return [styles.endIcon, styles[`iconSize${capitalize$2(ownerState.size)}`]];
	  }
	})(({
	  ownerState
	}) => _extends$1({
	  display: 'inherit',
	  marginRight: -4,
	  marginLeft: 8
	}, ownerState.size === 'small' && {
	  marginRight: -2
	}, commonIconStyles(ownerState)));
	const Button = /*#__PURE__*/reactExports.forwardRef(function Button(inProps, ref) {
	  // props priority: `inProps` > `contextProps` > `themeDefaultProps`
	  const contextProps = reactExports.useContext(ButtonGroupContext$1);
	  const buttonGroupButtonContextPositionClassName = reactExports.useContext(ButtonGroupButtonContext$1);
	  const resolvedProps = resolveProps(contextProps, inProps);
	  const props = useThemeProps({
	    props: resolvedProps,
	    name: 'MuiButton'
	  });
	  const {
	      children,
	      color = 'primary',
	      component = 'button',
	      className,
	      disabled = false,
	      disableElevation = false,
	      disableFocusRipple = false,
	      endIcon: endIconProp,
	      focusVisibleClassName,
	      fullWidth = false,
	      size = 'medium',
	      startIcon: startIconProp,
	      type,
	      variant = 'text'
	    } = props,
	    other = _objectWithoutPropertiesLoose(props, _excluded$d);
	  const ownerState = _extends$1({}, props, {
	    color,
	    component,
	    disabled,
	    disableElevation,
	    disableFocusRipple,
	    fullWidth,
	    size,
	    type,
	    variant
	  });
	  const classes = useUtilityClasses$a(ownerState);
	  const startIcon = startIconProp && /*#__PURE__*/jsxRuntimeExports.jsx(ButtonStartIcon, {
	    className: classes.startIcon,
	    ownerState: ownerState,
	    children: startIconProp
	  });
	  const endIcon = endIconProp && /*#__PURE__*/jsxRuntimeExports.jsx(ButtonEndIcon, {
	    className: classes.endIcon,
	    ownerState: ownerState,
	    children: endIconProp
	  });
	  const positionClassName = buttonGroupButtonContextPositionClassName || '';
	  return /*#__PURE__*/jsxRuntimeExports.jsxs(ButtonRoot, _extends$1({
	    ownerState: ownerState,
	    className: clsx(contextProps.className, classes.root, className, positionClassName),
	    component: component,
	    disabled: disabled,
	    focusRipple: !disableFocusRipple,
	    focusVisibleClassName: clsx(classes.focusVisible, focusVisibleClassName),
	    ref: ref,
	    type: type
	  }, other, {
	    classes: classes,
	    children: [startIcon, children, endIcon]
	  }));
	});
	var Button$1 = Button;

	function getButtonGroupUtilityClass(slot) {
	  return generateUtilityClass('MuiButtonGroup', slot);
	}
	const buttonGroupClasses = generateUtilityClasses('MuiButtonGroup', ['root', 'contained', 'outlined', 'text', 'disableElevation', 'disabled', 'firstButton', 'fullWidth', 'vertical', 'grouped', 'groupedHorizontal', 'groupedVertical', 'groupedText', 'groupedTextHorizontal', 'groupedTextVertical', 'groupedTextPrimary', 'groupedTextSecondary', 'groupedOutlined', 'groupedOutlinedHorizontal', 'groupedOutlinedVertical', 'groupedOutlinedPrimary', 'groupedOutlinedSecondary', 'groupedContained', 'groupedContainedHorizontal', 'groupedContainedVertical', 'groupedContainedPrimary', 'groupedContainedSecondary', 'lastButton', 'middleButton']);
	var buttonGroupClasses$1 = buttonGroupClasses;

	const _excluded$c = ["children", "className", "color", "component", "disabled", "disableElevation", "disableFocusRipple", "disableRipple", "fullWidth", "orientation", "size", "variant"];
	const overridesResolver$2 = (props, styles) => {
	  const {
	    ownerState
	  } = props;
	  return [{
	    [`& .${buttonGroupClasses$1.grouped}`]: styles.grouped
	  }, {
	    [`& .${buttonGroupClasses$1.grouped}`]: styles[`grouped${capitalize$2(ownerState.orientation)}`]
	  }, {
	    [`& .${buttonGroupClasses$1.grouped}`]: styles[`grouped${capitalize$2(ownerState.variant)}`]
	  }, {
	    [`& .${buttonGroupClasses$1.grouped}`]: styles[`grouped${capitalize$2(ownerState.variant)}${capitalize$2(ownerState.orientation)}`]
	  }, {
	    [`& .${buttonGroupClasses$1.grouped}`]: styles[`grouped${capitalize$2(ownerState.variant)}${capitalize$2(ownerState.color)}`]
	  }, {
	    [`& .${buttonGroupClasses$1.firstButton}`]: styles.firstButton
	  }, {
	    [`& .${buttonGroupClasses$1.lastButton}`]: styles.lastButton
	  }, {
	    [`& .${buttonGroupClasses$1.middleButton}`]: styles.middleButton
	  }, styles.root, styles[ownerState.variant], ownerState.disableElevation === true && styles.disableElevation, ownerState.fullWidth && styles.fullWidth, ownerState.orientation === 'vertical' && styles.vertical];
	};
	const useUtilityClasses$9 = ownerState => {
	  const {
	    classes,
	    color,
	    disabled,
	    disableElevation,
	    fullWidth,
	    orientation,
	    variant
	  } = ownerState;
	  const slots = {
	    root: ['root', variant, orientation === 'vertical' && 'vertical', fullWidth && 'fullWidth', disableElevation && 'disableElevation'],
	    grouped: ['grouped', `grouped${capitalize$2(orientation)}`, `grouped${capitalize$2(variant)}`, `grouped${capitalize$2(variant)}${capitalize$2(orientation)}`, `grouped${capitalize$2(variant)}${capitalize$2(color)}`, disabled && 'disabled'],
	    firstButton: ['firstButton'],
	    lastButton: ['lastButton'],
	    middleButton: ['middleButton']
	  };
	  return composeClasses(slots, getButtonGroupUtilityClass, classes);
	};
	const ButtonGroupRoot = styled$1('div', {
	  name: 'MuiButtonGroup',
	  slot: 'Root',
	  overridesResolver: overridesResolver$2
	})(({
	  theme,
	  ownerState
	}) => _extends$1({
	  display: 'inline-flex',
	  borderRadius: (theme.vars || theme).shape.borderRadius
	}, ownerState.variant === 'contained' && {
	  boxShadow: (theme.vars || theme).shadows[2]
	}, ownerState.disableElevation && {
	  boxShadow: 'none'
	}, ownerState.fullWidth && {
	  width: '100%'
	}, ownerState.orientation === 'vertical' && {
	  flexDirection: 'column'
	}, {
	  [`& .${buttonGroupClasses$1.grouped}`]: _extends$1({
	    minWidth: 40,
	    '&:hover': _extends$1({}, ownerState.variant === 'contained' && {
	      boxShadow: 'none'
	    })
	  }, ownerState.variant === 'contained' && {
	    boxShadow: 'none'
	  }),
	  [`& .${buttonGroupClasses$1.firstButton},& .${buttonGroupClasses$1.middleButton}`]: _extends$1({}, ownerState.orientation === 'horizontal' && {
	    borderTopRightRadius: 0,
	    borderBottomRightRadius: 0
	  }, ownerState.orientation === 'vertical' && {
	    borderBottomRightRadius: 0,
	    borderBottomLeftRadius: 0
	  }, ownerState.variant === 'text' && ownerState.orientation === 'horizontal' && {
	    borderRight: theme.vars ? `1px solid rgba(${theme.vars.palette.common.onBackgroundChannel} / 0.23)` : `1px solid ${theme.palette.mode === 'light' ? 'rgba(0, 0, 0, 0.23)' : 'rgba(255, 255, 255, 0.23)'}`,
	    [`&.${buttonGroupClasses$1.disabled}`]: {
	      borderRight: `1px solid ${(theme.vars || theme).palette.action.disabled}`
	    }
	  }, ownerState.variant === 'text' && ownerState.orientation === 'vertical' && {
	    borderBottom: theme.vars ? `1px solid rgba(${theme.vars.palette.common.onBackgroundChannel} / 0.23)` : `1px solid ${theme.palette.mode === 'light' ? 'rgba(0, 0, 0, 0.23)' : 'rgba(255, 255, 255, 0.23)'}`,
	    [`&.${buttonGroupClasses$1.disabled}`]: {
	      borderBottom: `1px solid ${(theme.vars || theme).palette.action.disabled}`
	    }
	  }, ownerState.variant === 'text' && ownerState.color !== 'inherit' && {
	    borderColor: theme.vars ? `rgba(${theme.vars.palette[ownerState.color].mainChannel} / 0.5)` : colorManipulatorExports.alpha(theme.palette[ownerState.color].main, 0.5)
	  }, ownerState.variant === 'outlined' && ownerState.orientation === 'horizontal' && {
	    borderRightColor: 'transparent'
	  }, ownerState.variant === 'outlined' && ownerState.orientation === 'vertical' && {
	    borderBottomColor: 'transparent'
	  }, ownerState.variant === 'contained' && ownerState.orientation === 'horizontal' && {
	    borderRight: `1px solid ${(theme.vars || theme).palette.grey[400]}`,
	    [`&.${buttonGroupClasses$1.disabled}`]: {
	      borderRight: `1px solid ${(theme.vars || theme).palette.action.disabled}`
	    }
	  }, ownerState.variant === 'contained' && ownerState.orientation === 'vertical' && {
	    borderBottom: `1px solid ${(theme.vars || theme).palette.grey[400]}`,
	    [`&.${buttonGroupClasses$1.disabled}`]: {
	      borderBottom: `1px solid ${(theme.vars || theme).palette.action.disabled}`
	    }
	  }, ownerState.variant === 'contained' && ownerState.color !== 'inherit' && {
	    borderColor: (theme.vars || theme).palette[ownerState.color].dark
	  }, {
	    '&:hover': _extends$1({}, ownerState.variant === 'outlined' && ownerState.orientation === 'horizontal' && {
	      borderRightColor: 'currentColor'
	    }, ownerState.variant === 'outlined' && ownerState.orientation === 'vertical' && {
	      borderBottomColor: 'currentColor'
	    })
	  }),
	  [`& .${buttonGroupClasses$1.lastButton},& .${buttonGroupClasses$1.middleButton}`]: _extends$1({}, ownerState.orientation === 'horizontal' && {
	    borderTopLeftRadius: 0,
	    borderBottomLeftRadius: 0
	  }, ownerState.orientation === 'vertical' && {
	    borderTopRightRadius: 0,
	    borderTopLeftRadius: 0
	  }, ownerState.variant === 'outlined' && ownerState.orientation === 'horizontal' && {
	    marginLeft: -1
	  }, ownerState.variant === 'outlined' && ownerState.orientation === 'vertical' && {
	    marginTop: -1
	  })
	}));
	const ButtonGroup = /*#__PURE__*/reactExports.forwardRef(function ButtonGroup(inProps, ref) {
	  const props = useThemeProps({
	    props: inProps,
	    name: 'MuiButtonGroup'
	  });
	  const {
	      children,
	      className,
	      color = 'primary',
	      component = 'div',
	      disabled = false,
	      disableElevation = false,
	      disableFocusRipple = false,
	      disableRipple = false,
	      fullWidth = false,
	      orientation = 'horizontal',
	      size = 'medium',
	      variant = 'outlined'
	    } = props,
	    other = _objectWithoutPropertiesLoose(props, _excluded$c);
	  const ownerState = _extends$1({}, props, {
	    color,
	    component,
	    disabled,
	    disableElevation,
	    disableFocusRipple,
	    disableRipple,
	    fullWidth,
	    orientation,
	    size,
	    variant
	  });
	  const classes = useUtilityClasses$9(ownerState);
	  const context = reactExports.useMemo(() => ({
	    className: classes.grouped,
	    color,
	    disabled,
	    disableElevation,
	    disableFocusRipple,
	    disableRipple,
	    fullWidth,
	    size,
	    variant
	  }), [color, disabled, disableElevation, disableFocusRipple, disableRipple, fullWidth, size, variant, classes.grouped]);
	  const validChildren = getValidReactChildren(children);
	  const childrenCount = validChildren.length;
	  const getButtonPositionClassName = index => {
	    const isFirstButton = index === 0;
	    const isLastButton = index === childrenCount - 1;
	    if (isFirstButton && isLastButton) {
	      return '';
	    }
	    if (isFirstButton) {
	      return classes.firstButton;
	    }
	    if (isLastButton) {
	      return classes.lastButton;
	    }
	    return classes.middleButton;
	  };
	  return /*#__PURE__*/jsxRuntimeExports.jsx(ButtonGroupRoot, _extends$1({
	    as: component,
	    role: "group",
	    className: clsx(classes.root, className),
	    ref: ref,
	    ownerState: ownerState
	  }, other, {
	    children: /*#__PURE__*/jsxRuntimeExports.jsx(ButtonGroupContext$1.Provider, {
	      value: context,
	      children: validChildren.map((child, index) => {
	        return /*#__PURE__*/jsxRuntimeExports.jsx(ButtonGroupButtonContext$1.Provider, {
	          value: getButtonPositionClassName(index),
	          children: child
	        }, index);
	      })
	    })
	  }));
	});
	var ButtonGroup$1 = ButtonGroup;

	function getCircularProgressUtilityClass(slot) {
	  return generateUtilityClass('MuiCircularProgress', slot);
	}
	generateUtilityClasses('MuiCircularProgress', ['root', 'determinate', 'indeterminate', 'colorPrimary', 'colorSecondary', 'svg', 'circle', 'circleDeterminate', 'circleIndeterminate', 'circleDisableShrink']);

	const _excluded$b = ["className", "color", "disableShrink", "size", "style", "thickness", "value", "variant"];
	let _ = t => t,
	  _t,
	  _t2,
	  _t3,
	  _t4;
	const SIZE = 44;
	const circularRotateKeyframe = keyframes(_t || (_t = _`
  0% {
    transform: rotate(0deg);
  }

  100% {
    transform: rotate(360deg);
  }
`));
	const circularDashKeyframe = keyframes(_t2 || (_t2 = _`
  0% {
    stroke-dasharray: 1px, 200px;
    stroke-dashoffset: 0;
  }

  50% {
    stroke-dasharray: 100px, 200px;
    stroke-dashoffset: -15px;
  }

  100% {
    stroke-dasharray: 100px, 200px;
    stroke-dashoffset: -125px;
  }
`));
	const useUtilityClasses$8 = ownerState => {
	  const {
	    classes,
	    variant,
	    color,
	    disableShrink
	  } = ownerState;
	  const slots = {
	    root: ['root', variant, `color${capitalize$2(color)}`],
	    svg: ['svg'],
	    circle: ['circle', `circle${capitalize$2(variant)}`, disableShrink && 'circleDisableShrink']
	  };
	  return composeClasses(slots, getCircularProgressUtilityClass, classes);
	};
	const CircularProgressRoot = styled$1('span', {
	  name: 'MuiCircularProgress',
	  slot: 'Root',
	  overridesResolver: (props, styles) => {
	    const {
	      ownerState
	    } = props;
	    return [styles.root, styles[ownerState.variant], styles[`color${capitalize$2(ownerState.color)}`]];
	  }
	})(({
	  ownerState,
	  theme
	}) => _extends$1({
	  display: 'inline-block'
	}, ownerState.variant === 'determinate' && {
	  transition: theme.transitions.create('transform')
	}, ownerState.color !== 'inherit' && {
	  color: (theme.vars || theme).palette[ownerState.color].main
	}), ({
	  ownerState
	}) => ownerState.variant === 'indeterminate' && css(_t3 || (_t3 = _`
      animation: ${0} 1.4s linear infinite;
    `), circularRotateKeyframe));
	const CircularProgressSVG = styled$1('svg', {
	  name: 'MuiCircularProgress',
	  slot: 'Svg',
	  overridesResolver: (props, styles) => styles.svg
	})({
	  display: 'block' // Keeps the progress centered
	});
	const CircularProgressCircle = styled$1('circle', {
	  name: 'MuiCircularProgress',
	  slot: 'Circle',
	  overridesResolver: (props, styles) => {
	    const {
	      ownerState
	    } = props;
	    return [styles.circle, styles[`circle${capitalize$2(ownerState.variant)}`], ownerState.disableShrink && styles.circleDisableShrink];
	  }
	})(({
	  ownerState,
	  theme
	}) => _extends$1({
	  stroke: 'currentColor'
	}, ownerState.variant === 'determinate' && {
	  transition: theme.transitions.create('stroke-dashoffset')
	}, ownerState.variant === 'indeterminate' && {
	  // Some default value that looks fine waiting for the animation to kicks in.
	  strokeDasharray: '80px, 200px',
	  strokeDashoffset: 0 // Add the unit to fix a Edge 16 and below bug.
	}), ({
	  ownerState
	}) => ownerState.variant === 'indeterminate' && !ownerState.disableShrink && css(_t4 || (_t4 = _`
      animation: ${0} 1.4s ease-in-out infinite;
    `), circularDashKeyframe));

	/**
	 * ## ARIA
	 *
	 * If the progress bar is describing the loading progress of a particular region of a page,
	 * you should use `aria-describedby` to point to the progress bar, and set the `aria-busy`
	 * attribute to `true` on that region until it has finished loading.
	 */
	const CircularProgress = /*#__PURE__*/reactExports.forwardRef(function CircularProgress(inProps, ref) {
	  const props = useThemeProps({
	    props: inProps,
	    name: 'MuiCircularProgress'
	  });
	  const {
	      className,
	      color = 'primary',
	      disableShrink = false,
	      size = 40,
	      style,
	      thickness = 3.6,
	      value = 0,
	      variant = 'indeterminate'
	    } = props,
	    other = _objectWithoutPropertiesLoose(props, _excluded$b);
	  const ownerState = _extends$1({}, props, {
	    color,
	    disableShrink,
	    size,
	    thickness,
	    value,
	    variant
	  });
	  const classes = useUtilityClasses$8(ownerState);
	  const circleStyle = {};
	  const rootStyle = {};
	  const rootProps = {};
	  if (variant === 'determinate') {
	    const circumference = 2 * Math.PI * ((SIZE - thickness) / 2);
	    circleStyle.strokeDasharray = circumference.toFixed(3);
	    rootProps['aria-valuenow'] = Math.round(value);
	    circleStyle.strokeDashoffset = `${((100 - value) / 100 * circumference).toFixed(3)}px`;
	    rootStyle.transform = 'rotate(-90deg)';
	  }
	  return /*#__PURE__*/jsxRuntimeExports.jsx(CircularProgressRoot, _extends$1({
	    className: clsx(classes.root, className),
	    style: _extends$1({
	      width: size,
	      height: size
	    }, rootStyle, style),
	    ownerState: ownerState,
	    ref: ref,
	    role: "progressbar"
	  }, rootProps, other, {
	    children: /*#__PURE__*/jsxRuntimeExports.jsx(CircularProgressSVG, {
	      className: classes.svg,
	      ownerState: ownerState,
	      viewBox: `${SIZE / 2} ${SIZE / 2} ${SIZE} ${SIZE}`,
	      children: /*#__PURE__*/jsxRuntimeExports.jsx(CircularProgressCircle, {
	        className: classes.circle,
	        style: circleStyle,
	        ownerState: ownerState,
	        cx: SIZE,
	        cy: SIZE,
	        r: (SIZE - thickness) / 2,
	        fill: "none",
	        strokeWidth: thickness
	      })
	    })
	  }));
	});
	var CircularProgress$1 = CircularProgress;

	function getModalUtilityClass(slot) {
	  return generateUtilityClass('MuiModal', slot);
	}
	generateUtilityClasses('MuiModal', ['root', 'hidden', 'backdrop']);

	const _excluded$a = ["BackdropComponent", "BackdropProps", "classes", "className", "closeAfterTransition", "children", "container", "component", "components", "componentsProps", "disableAutoFocus", "disableEnforceFocus", "disableEscapeKeyDown", "disablePortal", "disableRestoreFocus", "disableScrollLock", "hideBackdrop", "keepMounted", "onBackdropClick", "onClose", "onTransitionEnter", "onTransitionExited", "open", "slotProps", "slots", "theme"];
	const useUtilityClasses$7 = ownerState => {
	  const {
	    open,
	    exited,
	    classes
	  } = ownerState;
	  const slots = {
	    root: ['root', !open && exited && 'hidden'],
	    backdrop: ['backdrop']
	  };
	  return composeClasses(slots, getModalUtilityClass, classes);
	};
	const ModalRoot = styled$1('div', {
	  name: 'MuiModal',
	  slot: 'Root',
	  overridesResolver: (props, styles) => {
	    const {
	      ownerState
	    } = props;
	    return [styles.root, !ownerState.open && ownerState.exited && styles.hidden];
	  }
	})(({
	  theme,
	  ownerState
	}) => _extends$1({
	  position: 'fixed',
	  zIndex: (theme.vars || theme).zIndex.modal,
	  right: 0,
	  bottom: 0,
	  top: 0,
	  left: 0
	}, !ownerState.open && ownerState.exited && {
	  visibility: 'hidden'
	}));
	const ModalBackdrop = styled$1(Backdrop$1, {
	  name: 'MuiModal',
	  slot: 'Backdrop',
	  overridesResolver: (props, styles) => {
	    return styles.backdrop;
	  }
	})({
	  zIndex: -1
	});

	/**
	 * Modal is a lower-level construct that is leveraged by the following components:
	 *
	 * - [Dialog](/material-ui/api/dialog/)
	 * - [Drawer](/material-ui/api/drawer/)
	 * - [Menu](/material-ui/api/menu/)
	 * - [Popover](/material-ui/api/popover/)
	 *
	 * If you are creating a modal dialog, you probably want to use the [Dialog](/material-ui/api/dialog/) component
	 * rather than directly using Modal.
	 *
	 * This component shares many concepts with [react-overlays](https://react-bootstrap.github.io/react-overlays/#modals).
	 */
	const Modal = /*#__PURE__*/reactExports.forwardRef(function Modal(inProps, ref) {
	  var _ref, _slots$root, _ref2, _slots$backdrop, _slotProps$root, _slotProps$backdrop;
	  const props = useThemeProps({
	    name: 'MuiModal',
	    props: inProps
	  });
	  const {
	      BackdropComponent = ModalBackdrop,
	      BackdropProps,
	      className,
	      closeAfterTransition = false,
	      children,
	      container,
	      component,
	      components = {},
	      componentsProps = {},
	      disableAutoFocus = false,
	      disableEnforceFocus = false,
	      disableEscapeKeyDown = false,
	      disablePortal = false,
	      disableRestoreFocus = false,
	      disableScrollLock = false,
	      hideBackdrop = false,
	      keepMounted = false,
	      onBackdropClick,
	      open,
	      slotProps,
	      slots
	      // eslint-disable-next-line react/prop-types
	    } = props,
	    other = _objectWithoutPropertiesLoose(props, _excluded$a);
	  const propsWithDefaults = _extends$1({}, props, {
	    closeAfterTransition,
	    disableAutoFocus,
	    disableEnforceFocus,
	    disableEscapeKeyDown,
	    disablePortal,
	    disableRestoreFocus,
	    disableScrollLock,
	    hideBackdrop,
	    keepMounted
	  });
	  const {
	    getRootProps,
	    getBackdropProps,
	    getTransitionProps,
	    portalRef,
	    isTopModal,
	    exited,
	    hasTransition
	  } = useModal(_extends$1({}, propsWithDefaults, {
	    rootRef: ref
	  }));
	  const ownerState = _extends$1({}, propsWithDefaults, {
	    exited
	  });
	  const classes = useUtilityClasses$7(ownerState);
	  const childProps = {};
	  if (children.props.tabIndex === undefined) {
	    childProps.tabIndex = '-1';
	  }

	  // It's a Transition like component
	  if (hasTransition) {
	    const {
	      onEnter,
	      onExited
	    } = getTransitionProps();
	    childProps.onEnter = onEnter;
	    childProps.onExited = onExited;
	  }
	  const RootSlot = (_ref = (_slots$root = slots == null ? void 0 : slots.root) != null ? _slots$root : components.Root) != null ? _ref : ModalRoot;
	  const BackdropSlot = (_ref2 = (_slots$backdrop = slots == null ? void 0 : slots.backdrop) != null ? _slots$backdrop : components.Backdrop) != null ? _ref2 : BackdropComponent;
	  const rootSlotProps = (_slotProps$root = slotProps == null ? void 0 : slotProps.root) != null ? _slotProps$root : componentsProps.root;
	  const backdropSlotProps = (_slotProps$backdrop = slotProps == null ? void 0 : slotProps.backdrop) != null ? _slotProps$backdrop : componentsProps.backdrop;
	  const rootProps = useSlotProps({
	    elementType: RootSlot,
	    externalSlotProps: rootSlotProps,
	    externalForwardedProps: other,
	    getSlotProps: getRootProps,
	    additionalProps: {
	      ref,
	      as: component
	    },
	    ownerState,
	    className: clsx(className, rootSlotProps == null ? void 0 : rootSlotProps.className, classes == null ? void 0 : classes.root, !ownerState.open && ownerState.exited && (classes == null ? void 0 : classes.hidden))
	  });
	  const backdropProps = useSlotProps({
	    elementType: BackdropSlot,
	    externalSlotProps: backdropSlotProps,
	    additionalProps: BackdropProps,
	    getSlotProps: otherHandlers => {
	      return getBackdropProps(_extends$1({}, otherHandlers, {
	        onClick: e => {
	          if (onBackdropClick) {
	            onBackdropClick(e);
	          }
	          if (otherHandlers != null && otherHandlers.onClick) {
	            otherHandlers.onClick(e);
	          }
	        }
	      }));
	    },
	    className: clsx(backdropSlotProps == null ? void 0 : backdropSlotProps.className, BackdropProps == null ? void 0 : BackdropProps.className, classes == null ? void 0 : classes.backdrop),
	    ownerState
	  });
	  if (!keepMounted && !open && (!hasTransition || exited)) {
	    return null;
	  }
	  return /*#__PURE__*/jsxRuntimeExports.jsx(Portal, {
	    ref: portalRef,
	    container: container,
	    disablePortal: disablePortal,
	    children: /*#__PURE__*/jsxRuntimeExports.jsxs(RootSlot, _extends$1({}, rootProps, {
	      children: [!hideBackdrop && BackdropComponent ? /*#__PURE__*/jsxRuntimeExports.jsx(BackdropSlot, _extends$1({}, backdropProps)) : null, /*#__PURE__*/jsxRuntimeExports.jsx(FocusTrap, {
	        disableEnforceFocus: disableEnforceFocus,
	        disableAutoFocus: disableAutoFocus,
	        disableRestoreFocus: disableRestoreFocus,
	        isEnabled: isTopModal,
	        open: open,
	        children: /*#__PURE__*/reactExports.cloneElement(children, childProps)
	      })]
	    }))
	  });
	});
	var Modal$1 = Modal;

	function getDividerUtilityClass(slot) {
	  return generateUtilityClass('MuiDivider', slot);
	}
	const dividerClasses = generateUtilityClasses('MuiDivider', ['root', 'absolute', 'fullWidth', 'inset', 'middle', 'flexItem', 'light', 'vertical', 'withChildren', 'withChildrenVertical', 'textAlignRight', 'textAlignLeft', 'wrapper', 'wrapperVertical']);
	var dividerClasses$1 = dividerClasses;

	const _excluded$9 = ["absolute", "children", "className", "component", "flexItem", "light", "orientation", "role", "textAlign", "variant"];
	const useUtilityClasses$6 = ownerState => {
	  const {
	    absolute,
	    children,
	    classes,
	    flexItem,
	    light,
	    orientation,
	    textAlign,
	    variant
	  } = ownerState;
	  const slots = {
	    root: ['root', absolute && 'absolute', variant, light && 'light', orientation === 'vertical' && 'vertical', flexItem && 'flexItem', children && 'withChildren', children && orientation === 'vertical' && 'withChildrenVertical', textAlign === 'right' && orientation !== 'vertical' && 'textAlignRight', textAlign === 'left' && orientation !== 'vertical' && 'textAlignLeft'],
	    wrapper: ['wrapper', orientation === 'vertical' && 'wrapperVertical']
	  };
	  return composeClasses(slots, getDividerUtilityClass, classes);
	};
	const DividerRoot = styled$1('div', {
	  name: 'MuiDivider',
	  slot: 'Root',
	  overridesResolver: (props, styles) => {
	    const {
	      ownerState
	    } = props;
	    return [styles.root, ownerState.absolute && styles.absolute, styles[ownerState.variant], ownerState.light && styles.light, ownerState.orientation === 'vertical' && styles.vertical, ownerState.flexItem && styles.flexItem, ownerState.children && styles.withChildren, ownerState.children && ownerState.orientation === 'vertical' && styles.withChildrenVertical, ownerState.textAlign === 'right' && ownerState.orientation !== 'vertical' && styles.textAlignRight, ownerState.textAlign === 'left' && ownerState.orientation !== 'vertical' && styles.textAlignLeft];
	  }
	})(({
	  theme,
	  ownerState
	}) => _extends$1({
	  margin: 0,
	  // Reset browser default style.
	  flexShrink: 0,
	  borderWidth: 0,
	  borderStyle: 'solid',
	  borderColor: (theme.vars || theme).palette.divider,
	  borderBottomWidth: 'thin'
	}, ownerState.absolute && {
	  position: 'absolute',
	  bottom: 0,
	  left: 0,
	  width: '100%'
	}, ownerState.light && {
	  borderColor: theme.vars ? `rgba(${theme.vars.palette.dividerChannel} / 0.08)` : colorManipulatorExports.alpha(theme.palette.divider, 0.08)
	}, ownerState.variant === 'inset' && {
	  marginLeft: 72
	}, ownerState.variant === 'middle' && ownerState.orientation === 'horizontal' && {
	  marginLeft: theme.spacing(2),
	  marginRight: theme.spacing(2)
	}, ownerState.variant === 'middle' && ownerState.orientation === 'vertical' && {
	  marginTop: theme.spacing(1),
	  marginBottom: theme.spacing(1)
	}, ownerState.orientation === 'vertical' && {
	  height: '100%',
	  borderBottomWidth: 0,
	  borderRightWidth: 'thin'
	}, ownerState.flexItem && {
	  alignSelf: 'stretch',
	  height: 'auto'
	}), ({
	  ownerState
	}) => _extends$1({}, ownerState.children && {
	  display: 'flex',
	  whiteSpace: 'nowrap',
	  textAlign: 'center',
	  border: 0,
	  '&::before, &::after': {
	    content: '""',
	    alignSelf: 'center'
	  }
	}), ({
	  theme,
	  ownerState
	}) => _extends$1({}, ownerState.children && ownerState.orientation !== 'vertical' && {
	  '&::before, &::after': {
	    width: '100%',
	    borderTop: `thin solid ${(theme.vars || theme).palette.divider}`
	  }
	}), ({
	  theme,
	  ownerState
	}) => _extends$1({}, ownerState.children && ownerState.orientation === 'vertical' && {
	  flexDirection: 'column',
	  '&::before, &::after': {
	    height: '100%',
	    borderLeft: `thin solid ${(theme.vars || theme).palette.divider}`
	  }
	}), ({
	  ownerState
	}) => _extends$1({}, ownerState.textAlign === 'right' && ownerState.orientation !== 'vertical' && {
	  '&::before': {
	    width: '90%'
	  },
	  '&::after': {
	    width: '10%'
	  }
	}, ownerState.textAlign === 'left' && ownerState.orientation !== 'vertical' && {
	  '&::before': {
	    width: '10%'
	  },
	  '&::after': {
	    width: '90%'
	  }
	}));
	const DividerWrapper = styled$1('span', {
	  name: 'MuiDivider',
	  slot: 'Wrapper',
	  overridesResolver: (props, styles) => {
	    const {
	      ownerState
	    } = props;
	    return [styles.wrapper, ownerState.orientation === 'vertical' && styles.wrapperVertical];
	  }
	})(({
	  theme,
	  ownerState
	}) => _extends$1({
	  display: 'inline-block',
	  paddingLeft: `calc(${theme.spacing(1)} * 1.2)`,
	  paddingRight: `calc(${theme.spacing(1)} * 1.2)`
	}, ownerState.orientation === 'vertical' && {
	  paddingTop: `calc(${theme.spacing(1)} * 1.2)`,
	  paddingBottom: `calc(${theme.spacing(1)} * 1.2)`
	}));
	const Divider = /*#__PURE__*/reactExports.forwardRef(function Divider(inProps, ref) {
	  const props = useThemeProps({
	    props: inProps,
	    name: 'MuiDivider'
	  });
	  const {
	      absolute = false,
	      children,
	      className,
	      component = children ? 'div' : 'hr',
	      flexItem = false,
	      light = false,
	      orientation = 'horizontal',
	      role = component !== 'hr' ? 'separator' : undefined,
	      textAlign = 'center',
	      variant = 'fullWidth'
	    } = props,
	    other = _objectWithoutPropertiesLoose(props, _excluded$9);
	  const ownerState = _extends$1({}, props, {
	    absolute,
	    component,
	    flexItem,
	    light,
	    orientation,
	    role,
	    textAlign,
	    variant
	  });
	  const classes = useUtilityClasses$6(ownerState);
	  return /*#__PURE__*/jsxRuntimeExports.jsx(DividerRoot, _extends$1({
	    as: component,
	    className: clsx(classes.root, className),
	    role: role,
	    ref: ref,
	    ownerState: ownerState
	  }, other, {
	    children: children ? /*#__PURE__*/jsxRuntimeExports.jsx(DividerWrapper, {
	      className: classes.wrapper,
	      ownerState: ownerState,
	      children: children
	    }) : null
	  }));
	});

	/**
	 * The following flag is used to ensure that this component isn't tabbable i.e.
	 * does not get highlight/focus inside of MUI List.
	 */
	Divider.muiSkipListHighlight = true;
	var Divider$1 = Divider;

	const _excluded$8 = ["addEndListener", "appear", "children", "container", "direction", "easing", "in", "onEnter", "onEntered", "onEntering", "onExit", "onExited", "onExiting", "style", "timeout", "TransitionComponent"];
	function getTranslateValue(direction, node, resolvedContainer) {
	  const rect = node.getBoundingClientRect();
	  const containerRect = resolvedContainer && resolvedContainer.getBoundingClientRect();
	  const containerWindow = ownerWindow(node);
	  let transform;
	  if (node.fakeTransform) {
	    transform = node.fakeTransform;
	  } else {
	    const computedStyle = containerWindow.getComputedStyle(node);
	    transform = computedStyle.getPropertyValue('-webkit-transform') || computedStyle.getPropertyValue('transform');
	  }
	  let offsetX = 0;
	  let offsetY = 0;
	  if (transform && transform !== 'none' && typeof transform === 'string') {
	    const transformValues = transform.split('(')[1].split(')')[0].split(',');
	    offsetX = parseInt(transformValues[4], 10);
	    offsetY = parseInt(transformValues[5], 10);
	  }
	  if (direction === 'left') {
	    if (containerRect) {
	      return `translateX(${containerRect.right + offsetX - rect.left}px)`;
	    }
	    return `translateX(${containerWindow.innerWidth + offsetX - rect.left}px)`;
	  }
	  if (direction === 'right') {
	    if (containerRect) {
	      return `translateX(-${rect.right - containerRect.left - offsetX}px)`;
	    }
	    return `translateX(-${rect.left + rect.width - offsetX}px)`;
	  }
	  if (direction === 'up') {
	    if (containerRect) {
	      return `translateY(${containerRect.bottom + offsetY - rect.top}px)`;
	    }
	    return `translateY(${containerWindow.innerHeight + offsetY - rect.top}px)`;
	  }

	  // direction === 'down'
	  if (containerRect) {
	    return `translateY(-${rect.top - containerRect.top + rect.height - offsetY}px)`;
	  }
	  return `translateY(-${rect.top + rect.height - offsetY}px)`;
	}
	function resolveContainer(containerPropProp) {
	  return typeof containerPropProp === 'function' ? containerPropProp() : containerPropProp;
	}
	function setTranslateValue(direction, node, containerProp) {
	  const resolvedContainer = resolveContainer(containerProp);
	  const transform = getTranslateValue(direction, node, resolvedContainer);
	  if (transform) {
	    node.style.webkitTransform = transform;
	    node.style.transform = transform;
	  }
	}

	/**
	 * The Slide transition is used by the [Drawer](/material-ui/react-drawer/) component.
	 * It uses [react-transition-group](https://github.com/reactjs/react-transition-group) internally.
	 */
	const Slide = /*#__PURE__*/reactExports.forwardRef(function Slide(props, ref) {
	  const theme = useTheme();
	  const defaultEasing = {
	    enter: theme.transitions.easing.easeOut,
	    exit: theme.transitions.easing.sharp
	  };
	  const defaultTimeout = {
	    enter: theme.transitions.duration.enteringScreen,
	    exit: theme.transitions.duration.leavingScreen
	  };
	  const {
	      addEndListener,
	      appear = true,
	      children,
	      container: containerProp,
	      direction = 'down',
	      easing: easingProp = defaultEasing,
	      in: inProp,
	      onEnter,
	      onEntered,
	      onEntering,
	      onExit,
	      onExited,
	      onExiting,
	      style,
	      timeout = defaultTimeout,
	      // eslint-disable-next-line react/prop-types
	      TransitionComponent = Transition$1
	    } = props,
	    other = _objectWithoutPropertiesLoose(props, _excluded$8);
	  const childrenRef = reactExports.useRef(null);
	  const handleRef = useForkRef(children.ref, childrenRef, ref);
	  const normalizedTransitionCallback = callback => isAppearing => {
	    if (callback) {
	      // onEnterXxx and onExitXxx callbacks have a different arguments.length value.
	      if (isAppearing === undefined) {
	        callback(childrenRef.current);
	      } else {
	        callback(childrenRef.current, isAppearing);
	      }
	    }
	  };
	  const handleEnter = normalizedTransitionCallback((node, isAppearing) => {
	    setTranslateValue(direction, node, containerProp);
	    reflow(node);
	    if (onEnter) {
	      onEnter(node, isAppearing);
	    }
	  });
	  const handleEntering = normalizedTransitionCallback((node, isAppearing) => {
	    const transitionProps = getTransitionProps({
	      timeout,
	      style,
	      easing: easingProp
	    }, {
	      mode: 'enter'
	    });
	    node.style.webkitTransition = theme.transitions.create('-webkit-transform', _extends$1({}, transitionProps));
	    node.style.transition = theme.transitions.create('transform', _extends$1({}, transitionProps));
	    node.style.webkitTransform = 'none';
	    node.style.transform = 'none';
	    if (onEntering) {
	      onEntering(node, isAppearing);
	    }
	  });
	  const handleEntered = normalizedTransitionCallback(onEntered);
	  const handleExiting = normalizedTransitionCallback(onExiting);
	  const handleExit = normalizedTransitionCallback(node => {
	    const transitionProps = getTransitionProps({
	      timeout,
	      style,
	      easing: easingProp
	    }, {
	      mode: 'exit'
	    });
	    node.style.webkitTransition = theme.transitions.create('-webkit-transform', transitionProps);
	    node.style.transition = theme.transitions.create('transform', transitionProps);
	    setTranslateValue(direction, node, containerProp);
	    if (onExit) {
	      onExit(node);
	    }
	  });
	  const handleExited = normalizedTransitionCallback(node => {
	    // No need for transitions when the component is hidden
	    node.style.webkitTransition = '';
	    node.style.transition = '';
	    if (onExited) {
	      onExited(node);
	    }
	  });
	  const handleAddEndListener = next => {
	    if (addEndListener) {
	      // Old call signature before `react-transition-group` implemented `nodeRef`
	      addEndListener(childrenRef.current, next);
	    }
	  };
	  const updatePosition = reactExports.useCallback(() => {
	    if (childrenRef.current) {
	      setTranslateValue(direction, childrenRef.current, containerProp);
	    }
	  }, [direction, containerProp]);
	  reactExports.useEffect(() => {
	    // Skip configuration where the position is screen size invariant.
	    if (inProp || direction === 'down' || direction === 'right') {
	      return undefined;
	    }
	    const handleResize = debounce(() => {
	      if (childrenRef.current) {
	        setTranslateValue(direction, childrenRef.current, containerProp);
	      }
	    });
	    const containerWindow = ownerWindow(childrenRef.current);
	    containerWindow.addEventListener('resize', handleResize);
	    return () => {
	      handleResize.clear();
	      containerWindow.removeEventListener('resize', handleResize);
	    };
	  }, [direction, inProp, containerProp]);
	  reactExports.useEffect(() => {
	    if (!inProp) {
	      // We need to update the position of the drawer when the direction change and
	      // when it's hidden.
	      updatePosition();
	    }
	  }, [inProp, updatePosition]);
	  return /*#__PURE__*/jsxRuntimeExports.jsx(TransitionComponent, _extends$1({
	    nodeRef: childrenRef,
	    onEnter: handleEnter,
	    onEntered: handleEntered,
	    onEntering: handleEntering,
	    onExit: handleExit,
	    onExited: handleExited,
	    onExiting: handleExiting,
	    addEndListener: handleAddEndListener,
	    appear: appear,
	    in: inProp,
	    timeout: timeout
	  }, other, {
	    children: (state, childProps) => {
	      return /*#__PURE__*/reactExports.cloneElement(children, _extends$1({
	        ref: handleRef,
	        style: _extends$1({
	          visibility: state === 'exited' && !inProp ? 'hidden' : undefined
	        }, style, children.props.style)
	      }, childProps));
	    }
	  }));
	});
	var Slide$1 = Slide;

	function getDrawerUtilityClass(slot) {
	  return generateUtilityClass('MuiDrawer', slot);
	}
	generateUtilityClasses('MuiDrawer', ['root', 'docked', 'paper', 'paperAnchorLeft', 'paperAnchorRight', 'paperAnchorTop', 'paperAnchorBottom', 'paperAnchorDockedLeft', 'paperAnchorDockedRight', 'paperAnchorDockedTop', 'paperAnchorDockedBottom', 'modal']);

	const _excluded$7 = ["BackdropProps"],
	  _excluded2$2 = ["anchor", "BackdropProps", "children", "className", "elevation", "hideBackdrop", "ModalProps", "onClose", "open", "PaperProps", "SlideProps", "TransitionComponent", "transitionDuration", "variant"];
	const overridesResolver$1 = (props, styles) => {
	  const {
	    ownerState
	  } = props;
	  return [styles.root, (ownerState.variant === 'permanent' || ownerState.variant === 'persistent') && styles.docked, styles.modal];
	};
	const useUtilityClasses$5 = ownerState => {
	  const {
	    classes,
	    anchor,
	    variant
	  } = ownerState;
	  const slots = {
	    root: ['root'],
	    docked: [(variant === 'permanent' || variant === 'persistent') && 'docked'],
	    modal: ['modal'],
	    paper: ['paper', `paperAnchor${capitalize$2(anchor)}`, variant !== 'temporary' && `paperAnchorDocked${capitalize$2(anchor)}`]
	  };
	  return composeClasses(slots, getDrawerUtilityClass, classes);
	};
	const DrawerRoot = styled$1(Modal$1, {
	  name: 'MuiDrawer',
	  slot: 'Root',
	  overridesResolver: overridesResolver$1
	})(({
	  theme
	}) => ({
	  zIndex: (theme.vars || theme).zIndex.drawer
	}));
	const DrawerDockedRoot = styled$1('div', {
	  shouldForwardProp: rootShouldForwardProp$1,
	  name: 'MuiDrawer',
	  slot: 'Docked',
	  skipVariantsResolver: false,
	  overridesResolver: overridesResolver$1
	})({
	  flex: '0 0 auto'
	});
	const DrawerPaper = styled$1(Paper$1, {
	  name: 'MuiDrawer',
	  slot: 'Paper',
	  overridesResolver: (props, styles) => {
	    const {
	      ownerState
	    } = props;
	    return [styles.paper, styles[`paperAnchor${capitalize$2(ownerState.anchor)}`], ownerState.variant !== 'temporary' && styles[`paperAnchorDocked${capitalize$2(ownerState.anchor)}`]];
	  }
	})(({
	  theme,
	  ownerState
	}) => _extends$1({
	  overflowY: 'auto',
	  display: 'flex',
	  flexDirection: 'column',
	  height: '100%',
	  flex: '1 0 auto',
	  zIndex: (theme.vars || theme).zIndex.drawer,
	  // Add iOS momentum scrolling for iOS < 13.0
	  WebkitOverflowScrolling: 'touch',
	  // temporary style
	  position: 'fixed',
	  top: 0,
	  // We disable the focus ring for mouse, touch and keyboard users.
	  // At some point, it would be better to keep it for keyboard users.
	  // :focus-ring CSS pseudo-class will help.
	  outline: 0
	}, ownerState.anchor === 'left' && {
	  left: 0
	}, ownerState.anchor === 'top' && {
	  top: 0,
	  left: 0,
	  right: 0,
	  height: 'auto',
	  maxHeight: '100%'
	}, ownerState.anchor === 'right' && {
	  right: 0
	}, ownerState.anchor === 'bottom' && {
	  top: 'auto',
	  left: 0,
	  bottom: 0,
	  right: 0,
	  height: 'auto',
	  maxHeight: '100%'
	}, ownerState.anchor === 'left' && ownerState.variant !== 'temporary' && {
	  borderRight: `1px solid ${(theme.vars || theme).palette.divider}`
	}, ownerState.anchor === 'top' && ownerState.variant !== 'temporary' && {
	  borderBottom: `1px solid ${(theme.vars || theme).palette.divider}`
	}, ownerState.anchor === 'right' && ownerState.variant !== 'temporary' && {
	  borderLeft: `1px solid ${(theme.vars || theme).palette.divider}`
	}, ownerState.anchor === 'bottom' && ownerState.variant !== 'temporary' && {
	  borderTop: `1px solid ${(theme.vars || theme).palette.divider}`
	}));
	const oppositeDirection = {
	  left: 'right',
	  right: 'left',
	  top: 'down',
	  bottom: 'up'
	};
	function isHorizontal(anchor) {
	  return ['left', 'right'].indexOf(anchor) !== -1;
	}
	function getAnchor({
	  direction
	}, anchor) {
	  return direction === 'rtl' && isHorizontal(anchor) ? oppositeDirection[anchor] : anchor;
	}

	/**
	 * The props of the [Modal](/material-ui/api/modal/) component are available
	 * when `variant="temporary"` is set.
	 */
	const Drawer = /*#__PURE__*/reactExports.forwardRef(function Drawer(inProps, ref) {
	  const props = useThemeProps({
	    props: inProps,
	    name: 'MuiDrawer'
	  });
	  const theme = useTheme();
	  const isRtl = useRtl();
	  const defaultTransitionDuration = {
	    enter: theme.transitions.duration.enteringScreen,
	    exit: theme.transitions.duration.leavingScreen
	  };
	  const {
	      anchor: anchorProp = 'left',
	      BackdropProps,
	      children,
	      className,
	      elevation = 16,
	      hideBackdrop = false,
	      ModalProps: {
	        BackdropProps: BackdropPropsProp
	      } = {},
	      onClose,
	      open = false,
	      PaperProps = {},
	      SlideProps,
	      // eslint-disable-next-line react/prop-types
	      TransitionComponent = Slide$1,
	      transitionDuration = defaultTransitionDuration,
	      variant = 'temporary'
	    } = props,
	    ModalProps = _objectWithoutPropertiesLoose(props.ModalProps, _excluded$7),
	    other = _objectWithoutPropertiesLoose(props, _excluded2$2);

	  // Let's assume that the Drawer will always be rendered on user space.
	  // We use this state is order to skip the appear transition during the
	  // initial mount of the component.
	  const mounted = reactExports.useRef(false);
	  reactExports.useEffect(() => {
	    mounted.current = true;
	  }, []);
	  const anchorInvariant = getAnchor({
	    direction: isRtl ? 'rtl' : 'ltr'
	  }, anchorProp);
	  const anchor = anchorProp;
	  const ownerState = _extends$1({}, props, {
	    anchor,
	    elevation,
	    open,
	    variant
	  }, other);
	  const classes = useUtilityClasses$5(ownerState);
	  const drawer = /*#__PURE__*/jsxRuntimeExports.jsx(DrawerPaper, _extends$1({
	    elevation: variant === 'temporary' ? elevation : 0,
	    square: true
	  }, PaperProps, {
	    className: clsx(classes.paper, PaperProps.className),
	    ownerState: ownerState,
	    children: children
	  }));
	  if (variant === 'permanent') {
	    return /*#__PURE__*/jsxRuntimeExports.jsx(DrawerDockedRoot, _extends$1({
	      className: clsx(classes.root, classes.docked, className),
	      ownerState: ownerState,
	      ref: ref
	    }, other, {
	      children: drawer
	    }));
	  }
	  const slidingDrawer = /*#__PURE__*/jsxRuntimeExports.jsx(TransitionComponent, _extends$1({
	    in: open,
	    direction: oppositeDirection[anchorInvariant],
	    timeout: transitionDuration,
	    appear: mounted.current
	  }, SlideProps, {
	    children: drawer
	  }));
	  if (variant === 'persistent') {
	    return /*#__PURE__*/jsxRuntimeExports.jsx(DrawerDockedRoot, _extends$1({
	      className: clsx(classes.root, classes.docked, className),
	      ownerState: ownerState,
	      ref: ref
	    }, other, {
	      children: slidingDrawer
	    }));
	  }

	  // variant === temporary
	  return /*#__PURE__*/jsxRuntimeExports.jsx(DrawerRoot, _extends$1({
	    BackdropProps: _extends$1({}, BackdropProps, BackdropPropsProp, {
	      transitionDuration
	    }),
	    className: clsx(classes.root, classes.modal, className),
	    open: open,
	    ownerState: ownerState,
	    onClose: onClose,
	    hideBackdrop: hideBackdrop,
	    ref: ref
	  }, other, ModalProps, {
	    children: slidingDrawer
	  }));
	});
	var Drawer$1 = Drawer;

	const _excluded$6 = ["addEndListener", "appear", "children", "easing", "in", "onEnter", "onEntered", "onEntering", "onExit", "onExited", "onExiting", "style", "timeout", "TransitionComponent"];
	function getScale(value) {
	  return `scale(${value}, ${value ** 2})`;
	}
	const styles = {
	  entering: {
	    opacity: 1,
	    transform: getScale(1)
	  },
	  entered: {
	    opacity: 1,
	    transform: 'none'
	  }
	};

	/*
	 TODO v6: remove
	 Conditionally apply a workaround for the CSS transition bug in Safari 15.4 / WebKit browsers.
	 */
	const isWebKit154 = typeof navigator !== 'undefined' && /^((?!chrome|android).)*(safari|mobile)/i.test(navigator.userAgent) && /(os |version\/)15(.|_)4/i.test(navigator.userAgent);

	/**
	 * The Grow transition is used by the [Tooltip](/material-ui/react-tooltip/) and
	 * [Popover](/material-ui/react-popover/) components.
	 * It uses [react-transition-group](https://github.com/reactjs/react-transition-group) internally.
	 */
	const Grow = /*#__PURE__*/reactExports.forwardRef(function Grow(props, ref) {
	  const {
	      addEndListener,
	      appear = true,
	      children,
	      easing,
	      in: inProp,
	      onEnter,
	      onEntered,
	      onEntering,
	      onExit,
	      onExited,
	      onExiting,
	      style,
	      timeout = 'auto',
	      // eslint-disable-next-line react/prop-types
	      TransitionComponent = Transition$1
	    } = props,
	    other = _objectWithoutPropertiesLoose(props, _excluded$6);
	  const timer = useTimeout();
	  const autoTimeout = reactExports.useRef();
	  const theme = useTheme();
	  const nodeRef = reactExports.useRef(null);
	  const handleRef = useForkRef(nodeRef, children.ref, ref);
	  const normalizedTransitionCallback = callback => maybeIsAppearing => {
	    if (callback) {
	      const node = nodeRef.current;

	      // onEnterXxx and onExitXxx callbacks have a different arguments.length value.
	      if (maybeIsAppearing === undefined) {
	        callback(node);
	      } else {
	        callback(node, maybeIsAppearing);
	      }
	    }
	  };
	  const handleEntering = normalizedTransitionCallback(onEntering);
	  const handleEnter = normalizedTransitionCallback((node, isAppearing) => {
	    reflow(node); // So the animation always start from the start.

	    const {
	      duration: transitionDuration,
	      delay,
	      easing: transitionTimingFunction
	    } = getTransitionProps({
	      style,
	      timeout,
	      easing
	    }, {
	      mode: 'enter'
	    });
	    let duration;
	    if (timeout === 'auto') {
	      duration = theme.transitions.getAutoHeightDuration(node.clientHeight);
	      autoTimeout.current = duration;
	    } else {
	      duration = transitionDuration;
	    }
	    node.style.transition = [theme.transitions.create('opacity', {
	      duration,
	      delay
	    }), theme.transitions.create('transform', {
	      duration: isWebKit154 ? duration : duration * 0.666,
	      delay,
	      easing: transitionTimingFunction
	    })].join(',');
	    if (onEnter) {
	      onEnter(node, isAppearing);
	    }
	  });
	  const handleEntered = normalizedTransitionCallback(onEntered);
	  const handleExiting = normalizedTransitionCallback(onExiting);
	  const handleExit = normalizedTransitionCallback(node => {
	    const {
	      duration: transitionDuration,
	      delay,
	      easing: transitionTimingFunction
	    } = getTransitionProps({
	      style,
	      timeout,
	      easing
	    }, {
	      mode: 'exit'
	    });
	    let duration;
	    if (timeout === 'auto') {
	      duration = theme.transitions.getAutoHeightDuration(node.clientHeight);
	      autoTimeout.current = duration;
	    } else {
	      duration = transitionDuration;
	    }
	    node.style.transition = [theme.transitions.create('opacity', {
	      duration,
	      delay
	    }), theme.transitions.create('transform', {
	      duration: isWebKit154 ? duration : duration * 0.666,
	      delay: isWebKit154 ? delay : delay || duration * 0.333,
	      easing: transitionTimingFunction
	    })].join(',');
	    node.style.opacity = 0;
	    node.style.transform = getScale(0.75);
	    if (onExit) {
	      onExit(node);
	    }
	  });
	  const handleExited = normalizedTransitionCallback(onExited);
	  const handleAddEndListener = next => {
	    if (timeout === 'auto') {
	      timer.start(autoTimeout.current || 0, next);
	    }
	    if (addEndListener) {
	      // Old call signature before `react-transition-group` implemented `nodeRef`
	      addEndListener(nodeRef.current, next);
	    }
	  };
	  return /*#__PURE__*/jsxRuntimeExports.jsx(TransitionComponent, _extends$1({
	    appear: appear,
	    in: inProp,
	    nodeRef: nodeRef,
	    onEnter: handleEnter,
	    onEntered: handleEntered,
	    onEntering: handleEntering,
	    onExit: handleExit,
	    onExited: handleExited,
	    onExiting: handleExiting,
	    addEndListener: handleAddEndListener,
	    timeout: timeout === 'auto' ? null : timeout
	  }, other, {
	    children: (state, childProps) => {
	      return /*#__PURE__*/reactExports.cloneElement(children, _extends$1({
	        style: _extends$1({
	          opacity: 0,
	          transform: getScale(0.75),
	          visibility: state === 'exited' && !inProp ? 'hidden' : undefined
	        }, styles[state], style, children.props.style),
	        ref: handleRef
	      }, childProps));
	    }
	  }));
	});
	Grow.muiSupportAuto = true;
	var Grow$1 = Grow;

	/**
	 * @ignore - internal component.
	 */
	const ListContext = /*#__PURE__*/reactExports.createContext({});
	var ListContext$1 = ListContext;

	function getListUtilityClass(slot) {
	  return generateUtilityClass('MuiList', slot);
	}
	generateUtilityClasses('MuiList', ['root', 'padding', 'dense', 'subheader']);

	const _excluded$5 = ["children", "className", "component", "dense", "disablePadding", "subheader"];
	const useUtilityClasses$4 = ownerState => {
	  const {
	    classes,
	    disablePadding,
	    dense,
	    subheader
	  } = ownerState;
	  const slots = {
	    root: ['root', !disablePadding && 'padding', dense && 'dense', subheader && 'subheader']
	  };
	  return composeClasses(slots, getListUtilityClass, classes);
	};
	const ListRoot = styled$1('ul', {
	  name: 'MuiList',
	  slot: 'Root',
	  overridesResolver: (props, styles) => {
	    const {
	      ownerState
	    } = props;
	    return [styles.root, !ownerState.disablePadding && styles.padding, ownerState.dense && styles.dense, ownerState.subheader && styles.subheader];
	  }
	})(({
	  ownerState
	}) => _extends$1({
	  listStyle: 'none',
	  margin: 0,
	  padding: 0,
	  position: 'relative'
	}, !ownerState.disablePadding && {
	  paddingTop: 8,
	  paddingBottom: 8
	}, ownerState.subheader && {
	  paddingTop: 0
	}));
	const List = /*#__PURE__*/reactExports.forwardRef(function List(inProps, ref) {
	  const props = useThemeProps({
	    props: inProps,
	    name: 'MuiList'
	  });
	  const {
	      children,
	      className,
	      component = 'ul',
	      dense = false,
	      disablePadding = false,
	      subheader
	    } = props,
	    other = _objectWithoutPropertiesLoose(props, _excluded$5);
	  const context = reactExports.useMemo(() => ({
	    dense
	  }), [dense]);
	  const ownerState = _extends$1({}, props, {
	    component,
	    dense,
	    disablePadding
	  });
	  const classes = useUtilityClasses$4(ownerState);
	  return /*#__PURE__*/jsxRuntimeExports.jsx(ListContext$1.Provider, {
	    value: context,
	    children: /*#__PURE__*/jsxRuntimeExports.jsxs(ListRoot, _extends$1({
	      as: component,
	      className: clsx(classes.root, className),
	      ref: ref,
	      ownerState: ownerState
	    }, other, {
	      children: [subheader, children]
	    }))
	  });
	});
	var List$1 = List;

	const listItemIconClasses = generateUtilityClasses('MuiListItemIcon', ['root', 'alignItemsFlexStart']);
	var listItemIconClasses$1 = listItemIconClasses;

	const listItemTextClasses = generateUtilityClasses('MuiListItemText', ['root', 'multiline', 'dense', 'inset', 'primary', 'secondary']);
	var listItemTextClasses$1 = listItemTextClasses;

	const _excluded$4 = ["actions", "autoFocus", "autoFocusItem", "children", "className", "disabledItemsFocusable", "disableListWrap", "onKeyDown", "variant"];
	function nextItem(list, item, disableListWrap) {
	  if (list === item) {
	    return list.firstChild;
	  }
	  if (item && item.nextElementSibling) {
	    return item.nextElementSibling;
	  }
	  return disableListWrap ? null : list.firstChild;
	}
	function previousItem(list, item, disableListWrap) {
	  if (list === item) {
	    return disableListWrap ? list.firstChild : list.lastChild;
	  }
	  if (item && item.previousElementSibling) {
	    return item.previousElementSibling;
	  }
	  return disableListWrap ? null : list.lastChild;
	}
	function textCriteriaMatches(nextFocus, textCriteria) {
	  if (textCriteria === undefined) {
	    return true;
	  }
	  let text = nextFocus.innerText;
	  if (text === undefined) {
	    // jsdom doesn't support innerText
	    text = nextFocus.textContent;
	  }
	  text = text.trim().toLowerCase();
	  if (text.length === 0) {
	    return false;
	  }
	  if (textCriteria.repeating) {
	    return text[0] === textCriteria.keys[0];
	  }
	  return text.indexOf(textCriteria.keys.join('')) === 0;
	}
	function moveFocus(list, currentFocus, disableListWrap, disabledItemsFocusable, traversalFunction, textCriteria) {
	  let wrappedOnce = false;
	  let nextFocus = traversalFunction(list, currentFocus, currentFocus ? disableListWrap : false);
	  while (nextFocus) {
	    // Prevent infinite loop.
	    if (nextFocus === list.firstChild) {
	      if (wrappedOnce) {
	        return false;
	      }
	      wrappedOnce = true;
	    }

	    // Same logic as useAutocomplete.js
	    const nextFocusDisabled = disabledItemsFocusable ? false : nextFocus.disabled || nextFocus.getAttribute('aria-disabled') === 'true';
	    if (!nextFocus.hasAttribute('tabindex') || !textCriteriaMatches(nextFocus, textCriteria) || nextFocusDisabled) {
	      // Move to the next element.
	      nextFocus = traversalFunction(list, nextFocus, disableListWrap);
	    } else {
	      nextFocus.focus();
	      return true;
	    }
	  }
	  return false;
	}

	/**
	 * A permanently displayed menu following https://www.w3.org/WAI/ARIA/apg/patterns/menu-button/.
	 * It's exposed to help customization of the [`Menu`](/material-ui/api/menu/) component if you
	 * use it separately you need to move focus into the component manually. Once
	 * the focus is placed inside the component it is fully keyboard accessible.
	 */
	const MenuList = /*#__PURE__*/reactExports.forwardRef(function MenuList(props, ref) {
	  const {
	      // private
	      // eslint-disable-next-line react/prop-types
	      actions,
	      autoFocus = false,
	      autoFocusItem = false,
	      children,
	      className,
	      disabledItemsFocusable = false,
	      disableListWrap = false,
	      onKeyDown,
	      variant = 'selectedMenu'
	    } = props,
	    other = _objectWithoutPropertiesLoose(props, _excluded$4);
	  const listRef = reactExports.useRef(null);
	  const textCriteriaRef = reactExports.useRef({
	    keys: [],
	    repeating: true,
	    previousKeyMatched: true,
	    lastTime: null
	  });
	  useEnhancedEffect$1(() => {
	    if (autoFocus) {
	      listRef.current.focus();
	    }
	  }, [autoFocus]);
	  reactExports.useImperativeHandle(actions, () => ({
	    adjustStyleForScrollbar: (containerElement, {
	      direction
	    }) => {
	      // Let's ignore that piece of logic if users are already overriding the width
	      // of the menu.
	      const noExplicitWidth = !listRef.current.style.width;
	      if (containerElement.clientHeight < listRef.current.clientHeight && noExplicitWidth) {
	        const scrollbarSize = `${getScrollbarSize(ownerDocument(containerElement))}px`;
	        listRef.current.style[direction === 'rtl' ? 'paddingLeft' : 'paddingRight'] = scrollbarSize;
	        listRef.current.style.width = `calc(100% + ${scrollbarSize})`;
	      }
	      return listRef.current;
	    }
	  }), []);
	  const handleKeyDown = event => {
	    const list = listRef.current;
	    const key = event.key;
	    /**
	     * @type {Element} - will always be defined since we are in a keydown handler
	     * attached to an element. A keydown event is either dispatched to the activeElement
	     * or document.body or document.documentElement. Only the first case will
	     * trigger this specific handler.
	     */
	    const currentFocus = ownerDocument(list).activeElement;
	    if (key === 'ArrowDown') {
	      // Prevent scroll of the page
	      event.preventDefault();
	      moveFocus(list, currentFocus, disableListWrap, disabledItemsFocusable, nextItem);
	    } else if (key === 'ArrowUp') {
	      event.preventDefault();
	      moveFocus(list, currentFocus, disableListWrap, disabledItemsFocusable, previousItem);
	    } else if (key === 'Home') {
	      event.preventDefault();
	      moveFocus(list, null, disableListWrap, disabledItemsFocusable, nextItem);
	    } else if (key === 'End') {
	      event.preventDefault();
	      moveFocus(list, null, disableListWrap, disabledItemsFocusable, previousItem);
	    } else if (key.length === 1) {
	      const criteria = textCriteriaRef.current;
	      const lowerKey = key.toLowerCase();
	      const currTime = performance.now();
	      if (criteria.keys.length > 0) {
	        // Reset
	        if (currTime - criteria.lastTime > 500) {
	          criteria.keys = [];
	          criteria.repeating = true;
	          criteria.previousKeyMatched = true;
	        } else if (criteria.repeating && lowerKey !== criteria.keys[0]) {
	          criteria.repeating = false;
	        }
	      }
	      criteria.lastTime = currTime;
	      criteria.keys.push(lowerKey);
	      const keepFocusOnCurrent = currentFocus && !criteria.repeating && textCriteriaMatches(currentFocus, criteria);
	      if (criteria.previousKeyMatched && (keepFocusOnCurrent || moveFocus(list, currentFocus, false, disabledItemsFocusable, nextItem, criteria))) {
	        event.preventDefault();
	      } else {
	        criteria.previousKeyMatched = false;
	      }
	    }
	    if (onKeyDown) {
	      onKeyDown(event);
	    }
	  };
	  const handleRef = useForkRef(listRef, ref);

	  /**
	   * the index of the item should receive focus
	   * in a `variant="selectedMenu"` it's the first `selected` item
	   * otherwise it's the very first item.
	   */
	  let activeItemIndex = -1;
	  // since we inject focus related props into children we have to do a lookahead
	  // to check if there is a `selected` item. We're looking for the last `selected`
	  // item and use the first valid item as a fallback
	  reactExports.Children.forEach(children, (child, index) => {
	    if (! /*#__PURE__*/reactExports.isValidElement(child)) {
	      if (activeItemIndex === index) {
	        activeItemIndex += 1;
	        if (activeItemIndex >= children.length) {
	          // there are no focusable items within the list.
	          activeItemIndex = -1;
	        }
	      }
	      return;
	    }
	    if (!child.props.disabled) {
	      if (variant === 'selectedMenu' && child.props.selected) {
	        activeItemIndex = index;
	      } else if (activeItemIndex === -1) {
	        activeItemIndex = index;
	      }
	    }
	    if (activeItemIndex === index && (child.props.disabled || child.props.muiSkipListHighlight || child.type.muiSkipListHighlight)) {
	      activeItemIndex += 1;
	      if (activeItemIndex >= children.length) {
	        // there are no focusable items within the list.
	        activeItemIndex = -1;
	      }
	    }
	  });
	  const items = reactExports.Children.map(children, (child, index) => {
	    if (index === activeItemIndex) {
	      const newChildProps = {};
	      if (autoFocusItem) {
	        newChildProps.autoFocus = true;
	      }
	      if (child.props.tabIndex === undefined && variant === 'selectedMenu') {
	        newChildProps.tabIndex = 0;
	      }
	      return /*#__PURE__*/reactExports.cloneElement(child, newChildProps);
	    }
	    return child;
	  });
	  return /*#__PURE__*/jsxRuntimeExports.jsx(List$1, _extends$1({
	    role: "menu",
	    ref: handleRef,
	    className: className,
	    onKeyDown: handleKeyDown,
	    tabIndex: autoFocus ? 0 : -1
	  }, other, {
	    children: items
	  }));
	});
	var MenuList$1 = MenuList;

	function getPopoverUtilityClass(slot) {
	  return generateUtilityClass('MuiPopover', slot);
	}
	generateUtilityClasses('MuiPopover', ['root', 'paper']);

	const _excluded$3 = ["onEntering"],
	  _excluded2$1 = ["action", "anchorEl", "anchorOrigin", "anchorPosition", "anchorReference", "children", "className", "container", "elevation", "marginThreshold", "open", "PaperProps", "slots", "slotProps", "transformOrigin", "TransitionComponent", "transitionDuration", "TransitionProps", "disableScrollLock"],
	  _excluded3 = ["slotProps"];
	function getOffsetTop(rect, vertical) {
	  let offset = 0;
	  if (typeof vertical === 'number') {
	    offset = vertical;
	  } else if (vertical === 'center') {
	    offset = rect.height / 2;
	  } else if (vertical === 'bottom') {
	    offset = rect.height;
	  }
	  return offset;
	}
	function getOffsetLeft(rect, horizontal) {
	  let offset = 0;
	  if (typeof horizontal === 'number') {
	    offset = horizontal;
	  } else if (horizontal === 'center') {
	    offset = rect.width / 2;
	  } else if (horizontal === 'right') {
	    offset = rect.width;
	  }
	  return offset;
	}
	function getTransformOriginValue(transformOrigin) {
	  return [transformOrigin.horizontal, transformOrigin.vertical].map(n => typeof n === 'number' ? `${n}px` : n).join(' ');
	}
	function resolveAnchorEl(anchorEl) {
	  return typeof anchorEl === 'function' ? anchorEl() : anchorEl;
	}
	const useUtilityClasses$3 = ownerState => {
	  const {
	    classes
	  } = ownerState;
	  const slots = {
	    root: ['root'],
	    paper: ['paper']
	  };
	  return composeClasses(slots, getPopoverUtilityClass, classes);
	};
	const PopoverRoot = styled$1(Modal$1, {
	  name: 'MuiPopover',
	  slot: 'Root',
	  overridesResolver: (props, styles) => styles.root
	})({});
	const PopoverPaper = styled$1(Paper$1, {
	  name: 'MuiPopover',
	  slot: 'Paper',
	  overridesResolver: (props, styles) => styles.paper
	})({
	  position: 'absolute',
	  overflowY: 'auto',
	  overflowX: 'hidden',
	  // So we see the popover when it's empty.
	  // It's most likely on issue on userland.
	  minWidth: 16,
	  minHeight: 16,
	  maxWidth: 'calc(100% - 32px)',
	  maxHeight: 'calc(100% - 32px)',
	  // We disable the focus ring for mouse, touch and keyboard users.
	  outline: 0
	});
	const Popover = /*#__PURE__*/reactExports.forwardRef(function Popover(inProps, ref) {
	  var _slotProps$paper, _slots$root, _slots$paper;
	  const props = useThemeProps({
	    props: inProps,
	    name: 'MuiPopover'
	  });
	  const {
	      action,
	      anchorEl,
	      anchorOrigin = {
	        vertical: 'top',
	        horizontal: 'left'
	      },
	      anchorPosition,
	      anchorReference = 'anchorEl',
	      children,
	      className,
	      container: containerProp,
	      elevation = 8,
	      marginThreshold = 16,
	      open,
	      PaperProps: PaperPropsProp = {},
	      slots,
	      slotProps,
	      transformOrigin = {
	        vertical: 'top',
	        horizontal: 'left'
	      },
	      TransitionComponent = Grow$1,
	      transitionDuration: transitionDurationProp = 'auto',
	      TransitionProps: {
	        onEntering
	      } = {},
	      disableScrollLock = false
	    } = props,
	    TransitionProps = _objectWithoutPropertiesLoose(props.TransitionProps, _excluded$3),
	    other = _objectWithoutPropertiesLoose(props, _excluded2$1);
	  const externalPaperSlotProps = (_slotProps$paper = slotProps == null ? void 0 : slotProps.paper) != null ? _slotProps$paper : PaperPropsProp;
	  const paperRef = reactExports.useRef();
	  const handlePaperRef = useForkRef(paperRef, externalPaperSlotProps.ref);
	  const ownerState = _extends$1({}, props, {
	    anchorOrigin,
	    anchorReference,
	    elevation,
	    marginThreshold,
	    externalPaperSlotProps,
	    transformOrigin,
	    TransitionComponent,
	    transitionDuration: transitionDurationProp,
	    TransitionProps
	  });
	  const classes = useUtilityClasses$3(ownerState);

	  // Returns the top/left offset of the position
	  // to attach to on the anchor element (or body if none is provided)
	  const getAnchorOffset = reactExports.useCallback(() => {
	    if (anchorReference === 'anchorPosition') {
	      return anchorPosition;
	    }
	    const resolvedAnchorEl = resolveAnchorEl(anchorEl);

	    // If an anchor element wasn't provided, just use the parent body element of this Popover
	    const anchorElement = resolvedAnchorEl && resolvedAnchorEl.nodeType === 1 ? resolvedAnchorEl : ownerDocument(paperRef.current).body;
	    const anchorRect = anchorElement.getBoundingClientRect();
	    return {
	      top: anchorRect.top + getOffsetTop(anchorRect, anchorOrigin.vertical),
	      left: anchorRect.left + getOffsetLeft(anchorRect, anchorOrigin.horizontal)
	    };
	  }, [anchorEl, anchorOrigin.horizontal, anchorOrigin.vertical, anchorPosition, anchorReference]);

	  // Returns the base transform origin using the element
	  const getTransformOrigin = reactExports.useCallback(elemRect => {
	    return {
	      vertical: getOffsetTop(elemRect, transformOrigin.vertical),
	      horizontal: getOffsetLeft(elemRect, transformOrigin.horizontal)
	    };
	  }, [transformOrigin.horizontal, transformOrigin.vertical]);
	  const getPositioningStyle = reactExports.useCallback(element => {
	    const elemRect = {
	      width: element.offsetWidth,
	      height: element.offsetHeight
	    };

	    // Get the transform origin point on the element itself
	    const elemTransformOrigin = getTransformOrigin(elemRect);
	    if (anchorReference === 'none') {
	      return {
	        top: null,
	        left: null,
	        transformOrigin: getTransformOriginValue(elemTransformOrigin)
	      };
	    }

	    // Get the offset of the anchoring element
	    const anchorOffset = getAnchorOffset();

	    // Calculate element positioning
	    let top = anchorOffset.top - elemTransformOrigin.vertical;
	    let left = anchorOffset.left - elemTransformOrigin.horizontal;
	    const bottom = top + elemRect.height;
	    const right = left + elemRect.width;

	    // Use the parent window of the anchorEl if provided
	    const containerWindow = ownerWindow(resolveAnchorEl(anchorEl));

	    // Window thresholds taking required margin into account
	    const heightThreshold = containerWindow.innerHeight - marginThreshold;
	    const widthThreshold = containerWindow.innerWidth - marginThreshold;

	    // Check if the vertical axis needs shifting
	    if (marginThreshold !== null && top < marginThreshold) {
	      const diff = top - marginThreshold;
	      top -= diff;
	      elemTransformOrigin.vertical += diff;
	    } else if (marginThreshold !== null && bottom > heightThreshold) {
	      const diff = bottom - heightThreshold;
	      top -= diff;
	      elemTransformOrigin.vertical += diff;
	    }

	    // Check if the horizontal axis needs shifting
	    if (marginThreshold !== null && left < marginThreshold) {
	      const diff = left - marginThreshold;
	      left -= diff;
	      elemTransformOrigin.horizontal += diff;
	    } else if (right > widthThreshold) {
	      const diff = right - widthThreshold;
	      left -= diff;
	      elemTransformOrigin.horizontal += diff;
	    }
	    return {
	      top: `${Math.round(top)}px`,
	      left: `${Math.round(left)}px`,
	      transformOrigin: getTransformOriginValue(elemTransformOrigin)
	    };
	  }, [anchorEl, anchorReference, getAnchorOffset, getTransformOrigin, marginThreshold]);
	  const [isPositioned, setIsPositioned] = reactExports.useState(open);
	  const setPositioningStyles = reactExports.useCallback(() => {
	    const element = paperRef.current;
	    if (!element) {
	      return;
	    }
	    const positioning = getPositioningStyle(element);
	    if (positioning.top !== null) {
	      element.style.top = positioning.top;
	    }
	    if (positioning.left !== null) {
	      element.style.left = positioning.left;
	    }
	    element.style.transformOrigin = positioning.transformOrigin;
	    setIsPositioned(true);
	  }, [getPositioningStyle]);
	  reactExports.useEffect(() => {
	    if (disableScrollLock) {
	      window.addEventListener('scroll', setPositioningStyles);
	    }
	    return () => window.removeEventListener('scroll', setPositioningStyles);
	  }, [anchorEl, disableScrollLock, setPositioningStyles]);
	  const handleEntering = (element, isAppearing) => {
	    if (onEntering) {
	      onEntering(element, isAppearing);
	    }
	    setPositioningStyles();
	  };
	  const handleExited = () => {
	    setIsPositioned(false);
	  };
	  reactExports.useEffect(() => {
	    if (open) {
	      setPositioningStyles();
	    }
	  });
	  reactExports.useImperativeHandle(action, () => open ? {
	    updatePosition: () => {
	      setPositioningStyles();
	    }
	  } : null, [open, setPositioningStyles]);
	  reactExports.useEffect(() => {
	    if (!open) {
	      return undefined;
	    }
	    const handleResize = debounce(() => {
	      setPositioningStyles();
	    });
	    const containerWindow = ownerWindow(anchorEl);
	    containerWindow.addEventListener('resize', handleResize);
	    return () => {
	      handleResize.clear();
	      containerWindow.removeEventListener('resize', handleResize);
	    };
	  }, [anchorEl, open, setPositioningStyles]);
	  let transitionDuration = transitionDurationProp;
	  if (transitionDurationProp === 'auto' && !TransitionComponent.muiSupportAuto) {
	    transitionDuration = undefined;
	  }

	  // If the container prop is provided, use that
	  // If the anchorEl prop is provided, use its parent body element as the container
	  // If neither are provided let the Modal take care of choosing the container
	  const container = containerProp || (anchorEl ? ownerDocument(resolveAnchorEl(anchorEl)).body : undefined);
	  const RootSlot = (_slots$root = slots == null ? void 0 : slots.root) != null ? _slots$root : PopoverRoot;
	  const PaperSlot = (_slots$paper = slots == null ? void 0 : slots.paper) != null ? _slots$paper : PopoverPaper;
	  const paperProps = useSlotProps({
	    elementType: PaperSlot,
	    externalSlotProps: _extends$1({}, externalPaperSlotProps, {
	      style: isPositioned ? externalPaperSlotProps.style : _extends$1({}, externalPaperSlotProps.style, {
	        opacity: 0
	      })
	    }),
	    additionalProps: {
	      elevation,
	      ref: handlePaperRef
	    },
	    ownerState,
	    className: clsx(classes.paper, externalPaperSlotProps == null ? void 0 : externalPaperSlotProps.className)
	  });
	  const _useSlotProps = useSlotProps({
	      elementType: RootSlot,
	      externalSlotProps: (slotProps == null ? void 0 : slotProps.root) || {},
	      externalForwardedProps: other,
	      additionalProps: {
	        ref,
	        slotProps: {
	          backdrop: {
	            invisible: true
	          }
	        },
	        container,
	        open
	      },
	      ownerState,
	      className: clsx(classes.root, className)
	    }),
	    {
	      slotProps: rootSlotPropsProp
	    } = _useSlotProps,
	    rootProps = _objectWithoutPropertiesLoose(_useSlotProps, _excluded3);
	  return /*#__PURE__*/jsxRuntimeExports.jsx(RootSlot, _extends$1({}, rootProps, !isHostComponent(RootSlot) && {
	    slotProps: rootSlotPropsProp,
	    disableScrollLock
	  }, {
	    children: /*#__PURE__*/jsxRuntimeExports.jsx(TransitionComponent, _extends$1({
	      appear: true,
	      in: open,
	      onEntering: handleEntering,
	      onExited: handleExited,
	      timeout: transitionDuration
	    }, TransitionProps, {
	      children: /*#__PURE__*/jsxRuntimeExports.jsx(PaperSlot, _extends$1({}, paperProps, {
	        children: children
	      }))
	    }))
	  }));
	});
	var Popover$1 = Popover;

	function getMenuUtilityClass(slot) {
	  return generateUtilityClass('MuiMenu', slot);
	}
	generateUtilityClasses('MuiMenu', ['root', 'paper', 'list']);

	const _excluded$2 = ["onEntering"],
	  _excluded2 = ["autoFocus", "children", "className", "disableAutoFocusItem", "MenuListProps", "onClose", "open", "PaperProps", "PopoverClasses", "transitionDuration", "TransitionProps", "variant", "slots", "slotProps"];
	const RTL_ORIGIN = {
	  vertical: 'top',
	  horizontal: 'right'
	};
	const LTR_ORIGIN = {
	  vertical: 'top',
	  horizontal: 'left'
	};
	const useUtilityClasses$2 = ownerState => {
	  const {
	    classes
	  } = ownerState;
	  const slots = {
	    root: ['root'],
	    paper: ['paper'],
	    list: ['list']
	  };
	  return composeClasses(slots, getMenuUtilityClass, classes);
	};
	const MenuRoot = styled$1(Popover$1, {
	  shouldForwardProp: prop => rootShouldForwardProp$1(prop) || prop === 'classes',
	  name: 'MuiMenu',
	  slot: 'Root',
	  overridesResolver: (props, styles) => styles.root
	})({});
	const MenuPaper = styled$1(PopoverPaper, {
	  name: 'MuiMenu',
	  slot: 'Paper',
	  overridesResolver: (props, styles) => styles.paper
	})({
	  // specZ: The maximum height of a simple menu should be one or more rows less than the view
	  // height. This ensures a tappable area outside of the simple menu with which to dismiss
	  // the menu.
	  maxHeight: 'calc(100% - 96px)',
	  // Add iOS momentum scrolling for iOS < 13.0
	  WebkitOverflowScrolling: 'touch'
	});
	const MenuMenuList = styled$1(MenuList$1, {
	  name: 'MuiMenu',
	  slot: 'List',
	  overridesResolver: (props, styles) => styles.list
	})({
	  // We disable the focus ring for mouse, touch and keyboard users.
	  outline: 0
	});
	const Menu = /*#__PURE__*/reactExports.forwardRef(function Menu(inProps, ref) {
	  var _slots$paper, _slotProps$paper;
	  const props = useThemeProps({
	    props: inProps,
	    name: 'MuiMenu'
	  });
	  const {
	      autoFocus = true,
	      children,
	      className,
	      disableAutoFocusItem = false,
	      MenuListProps = {},
	      onClose,
	      open,
	      PaperProps = {},
	      PopoverClasses,
	      transitionDuration = 'auto',
	      TransitionProps: {
	        onEntering
	      } = {},
	      variant = 'selectedMenu',
	      slots = {},
	      slotProps = {}
	    } = props,
	    TransitionProps = _objectWithoutPropertiesLoose(props.TransitionProps, _excluded$2),
	    other = _objectWithoutPropertiesLoose(props, _excluded2);
	  const isRtl = useRtl();
	  const ownerState = _extends$1({}, props, {
	    autoFocus,
	    disableAutoFocusItem,
	    MenuListProps,
	    onEntering,
	    PaperProps,
	    transitionDuration,
	    TransitionProps,
	    variant
	  });
	  const classes = useUtilityClasses$2(ownerState);
	  const autoFocusItem = autoFocus && !disableAutoFocusItem && open;
	  const menuListActionsRef = reactExports.useRef(null);
	  const handleEntering = (element, isAppearing) => {
	    if (menuListActionsRef.current) {
	      menuListActionsRef.current.adjustStyleForScrollbar(element, {
	        direction: isRtl ? 'rtl' : 'ltr'
	      });
	    }
	    if (onEntering) {
	      onEntering(element, isAppearing);
	    }
	  };
	  const handleListKeyDown = event => {
	    if (event.key === 'Tab') {
	      event.preventDefault();
	      if (onClose) {
	        onClose(event, 'tabKeyDown');
	      }
	    }
	  };

	  /**
	   * the index of the item should receive focus
	   * in a `variant="selectedMenu"` it's the first `selected` item
	   * otherwise it's the very first item.
	   */
	  let activeItemIndex = -1;
	  // since we inject focus related props into children we have to do a lookahead
	  // to check if there is a `selected` item. We're looking for the last `selected`
	  // item and use the first valid item as a fallback
	  reactExports.Children.map(children, (child, index) => {
	    if (! /*#__PURE__*/reactExports.isValidElement(child)) {
	      return;
	    }
	    if (!child.props.disabled) {
	      if (variant === 'selectedMenu' && child.props.selected) {
	        activeItemIndex = index;
	      } else if (activeItemIndex === -1) {
	        activeItemIndex = index;
	      }
	    }
	  });
	  const PaperSlot = (_slots$paper = slots.paper) != null ? _slots$paper : MenuPaper;
	  const paperExternalSlotProps = (_slotProps$paper = slotProps.paper) != null ? _slotProps$paper : PaperProps;
	  const rootSlotProps = useSlotProps({
	    elementType: slots.root,
	    externalSlotProps: slotProps.root,
	    ownerState,
	    className: [classes.root, className]
	  });
	  const paperSlotProps = useSlotProps({
	    elementType: PaperSlot,
	    externalSlotProps: paperExternalSlotProps,
	    ownerState,
	    className: classes.paper
	  });
	  return /*#__PURE__*/jsxRuntimeExports.jsx(MenuRoot, _extends$1({
	    onClose: onClose,
	    anchorOrigin: {
	      vertical: 'bottom',
	      horizontal: isRtl ? 'right' : 'left'
	    },
	    transformOrigin: isRtl ? RTL_ORIGIN : LTR_ORIGIN,
	    slots: {
	      paper: PaperSlot,
	      root: slots.root
	    },
	    slotProps: {
	      root: rootSlotProps,
	      paper: paperSlotProps
	    },
	    open: open,
	    ref: ref,
	    transitionDuration: transitionDuration,
	    TransitionProps: _extends$1({
	      onEntering: handleEntering
	    }, TransitionProps),
	    ownerState: ownerState
	  }, other, {
	    classes: PopoverClasses,
	    children: /*#__PURE__*/jsxRuntimeExports.jsx(MenuMenuList, _extends$1({
	      onKeyDown: handleListKeyDown,
	      actions: menuListActionsRef,
	      autoFocus: autoFocus && (activeItemIndex === -1 || disableAutoFocusItem),
	      autoFocusItem: autoFocusItem,
	      variant: variant
	    }, MenuListProps, {
	      className: clsx(classes.list, MenuListProps.className),
	      children: children
	    }))
	  }));
	});
	var Menu$1 = Menu;

	function getMenuItemUtilityClass(slot) {
	  return generateUtilityClass('MuiMenuItem', slot);
	}
	const menuItemClasses = generateUtilityClasses('MuiMenuItem', ['root', 'focusVisible', 'dense', 'disabled', 'divider', 'gutters', 'selected']);
	var menuItemClasses$1 = menuItemClasses;

	const _excluded$1 = ["autoFocus", "component", "dense", "divider", "disableGutters", "focusVisibleClassName", "role", "tabIndex", "className"];
	const overridesResolver = (props, styles) => {
	  const {
	    ownerState
	  } = props;
	  return [styles.root, ownerState.dense && styles.dense, ownerState.divider && styles.divider, !ownerState.disableGutters && styles.gutters];
	};
	const useUtilityClasses$1 = ownerState => {
	  const {
	    disabled,
	    dense,
	    divider,
	    disableGutters,
	    selected,
	    classes
	  } = ownerState;
	  const slots = {
	    root: ['root', dense && 'dense', disabled && 'disabled', !disableGutters && 'gutters', divider && 'divider', selected && 'selected']
	  };
	  const composedClasses = composeClasses(slots, getMenuItemUtilityClass, classes);
	  return _extends$1({}, classes, composedClasses);
	};
	const MenuItemRoot = styled$1(ButtonBase$1, {
	  shouldForwardProp: prop => rootShouldForwardProp$1(prop) || prop === 'classes',
	  name: 'MuiMenuItem',
	  slot: 'Root',
	  overridesResolver
	})(({
	  theme,
	  ownerState
	}) => _extends$1({}, theme.typography.body1, {
	  display: 'flex',
	  justifyContent: 'flex-start',
	  alignItems: 'center',
	  position: 'relative',
	  textDecoration: 'none',
	  minHeight: 48,
	  paddingTop: 6,
	  paddingBottom: 6,
	  boxSizing: 'border-box',
	  whiteSpace: 'nowrap'
	}, !ownerState.disableGutters && {
	  paddingLeft: 16,
	  paddingRight: 16
	}, ownerState.divider && {
	  borderBottom: `1px solid ${(theme.vars || theme).palette.divider}`,
	  backgroundClip: 'padding-box'
	}, {
	  '&:hover': {
	    textDecoration: 'none',
	    backgroundColor: (theme.vars || theme).palette.action.hover,
	    // Reset on touch devices, it doesn't add specificity
	    '@media (hover: none)': {
	      backgroundColor: 'transparent'
	    }
	  },
	  [`&.${menuItemClasses$1.selected}`]: {
	    backgroundColor: theme.vars ? `rgba(${theme.vars.palette.primary.mainChannel} / ${theme.vars.palette.action.selectedOpacity})` : colorManipulatorExports.alpha(theme.palette.primary.main, theme.palette.action.selectedOpacity),
	    [`&.${menuItemClasses$1.focusVisible}`]: {
	      backgroundColor: theme.vars ? `rgba(${theme.vars.palette.primary.mainChannel} / calc(${theme.vars.palette.action.selectedOpacity} + ${theme.vars.palette.action.focusOpacity}))` : colorManipulatorExports.alpha(theme.palette.primary.main, theme.palette.action.selectedOpacity + theme.palette.action.focusOpacity)
	    }
	  },
	  [`&.${menuItemClasses$1.selected}:hover`]: {
	    backgroundColor: theme.vars ? `rgba(${theme.vars.palette.primary.mainChannel} / calc(${theme.vars.palette.action.selectedOpacity} + ${theme.vars.palette.action.hoverOpacity}))` : colorManipulatorExports.alpha(theme.palette.primary.main, theme.palette.action.selectedOpacity + theme.palette.action.hoverOpacity),
	    // Reset on touch devices, it doesn't add specificity
	    '@media (hover: none)': {
	      backgroundColor: theme.vars ? `rgba(${theme.vars.palette.primary.mainChannel} / ${theme.vars.palette.action.selectedOpacity})` : colorManipulatorExports.alpha(theme.palette.primary.main, theme.palette.action.selectedOpacity)
	    }
	  },
	  [`&.${menuItemClasses$1.focusVisible}`]: {
	    backgroundColor: (theme.vars || theme).palette.action.focus
	  },
	  [`&.${menuItemClasses$1.disabled}`]: {
	    opacity: (theme.vars || theme).palette.action.disabledOpacity
	  },
	  [`& + .${dividerClasses$1.root}`]: {
	    marginTop: theme.spacing(1),
	    marginBottom: theme.spacing(1)
	  },
	  [`& + .${dividerClasses$1.inset}`]: {
	    marginLeft: 52
	  },
	  [`& .${listItemTextClasses$1.root}`]: {
	    marginTop: 0,
	    marginBottom: 0
	  },
	  [`& .${listItemTextClasses$1.inset}`]: {
	    paddingLeft: 36
	  },
	  [`& .${listItemIconClasses$1.root}`]: {
	    minWidth: 36
	  }
	}, !ownerState.dense && {
	  [theme.breakpoints.up('sm')]: {
	    minHeight: 'auto'
	  }
	}, ownerState.dense && _extends$1({
	  minHeight: 32,
	  // https://m2.material.io/components/menus#specs > Dense
	  paddingTop: 4,
	  paddingBottom: 4
	}, theme.typography.body2, {
	  [`& .${listItemIconClasses$1.root} svg`]: {
	    fontSize: '1.25rem'
	  }
	})));
	const MenuItem = /*#__PURE__*/reactExports.forwardRef(function MenuItem(inProps, ref) {
	  const props = useThemeProps({
	    props: inProps,
	    name: 'MuiMenuItem'
	  });
	  const {
	      autoFocus = false,
	      component = 'li',
	      dense = false,
	      divider = false,
	      disableGutters = false,
	      focusVisibleClassName,
	      role = 'menuitem',
	      tabIndex: tabIndexProp,
	      className
	    } = props,
	    other = _objectWithoutPropertiesLoose(props, _excluded$1);
	  const context = reactExports.useContext(ListContext$1);
	  const childContext = reactExports.useMemo(() => ({
	    dense: dense || context.dense || false,
	    disableGutters
	  }), [context.dense, dense, disableGutters]);
	  const menuItemRef = reactExports.useRef(null);
	  useEnhancedEffect$1(() => {
	    if (autoFocus) {
	      if (menuItemRef.current) {
	        menuItemRef.current.focus();
	      }
	    }
	  }, [autoFocus]);
	  const ownerState = _extends$1({}, props, {
	    dense: childContext.dense,
	    divider,
	    disableGutters
	  });
	  const classes = useUtilityClasses$1(props);
	  const handleRef = useForkRef(menuItemRef, ref);
	  let tabIndex;
	  if (!props.disabled) {
	    tabIndex = tabIndexProp !== undefined ? tabIndexProp : -1;
	  }
	  return /*#__PURE__*/jsxRuntimeExports.jsx(ListContext$1.Provider, {
	    value: childContext,
	    children: /*#__PURE__*/jsxRuntimeExports.jsx(MenuItemRoot, _extends$1({
	      ref: handleRef,
	      role: role,
	      tabIndex: tabIndex,
	      component: component,
	      focusVisibleClassName: clsx(classes.focusVisible, focusVisibleClassName),
	      className: clsx(classes.root, className)
	    }, other, {
	      ownerState: ownerState,
	      classes: classes
	    }))
	  });
	});
	var MenuItem$1 = MenuItem;

	function getToolbarUtilityClass(slot) {
	  return generateUtilityClass('MuiToolbar', slot);
	}
	generateUtilityClasses('MuiToolbar', ['root', 'gutters', 'regular', 'dense']);

	const _excluded = ["className", "component", "disableGutters", "variant"];
	const useUtilityClasses = ownerState => {
	  const {
	    classes,
	    disableGutters,
	    variant
	  } = ownerState;
	  const slots = {
	    root: ['root', !disableGutters && 'gutters', variant]
	  };
	  return composeClasses(slots, getToolbarUtilityClass, classes);
	};
	const ToolbarRoot = styled$1('div', {
	  name: 'MuiToolbar',
	  slot: 'Root',
	  overridesResolver: (props, styles) => {
	    const {
	      ownerState
	    } = props;
	    return [styles.root, !ownerState.disableGutters && styles.gutters, styles[ownerState.variant]];
	  }
	})(({
	  theme,
	  ownerState
	}) => _extends$1({
	  position: 'relative',
	  display: 'flex',
	  alignItems: 'center'
	}, !ownerState.disableGutters && {
	  paddingLeft: theme.spacing(2),
	  paddingRight: theme.spacing(2),
	  [theme.breakpoints.up('sm')]: {
	    paddingLeft: theme.spacing(3),
	    paddingRight: theme.spacing(3)
	  }
	}, ownerState.variant === 'dense' && {
	  minHeight: 48
	}), ({
	  theme,
	  ownerState
	}) => ownerState.variant === 'regular' && theme.mixins.toolbar);
	const Toolbar = /*#__PURE__*/reactExports.forwardRef(function Toolbar(inProps, ref) {
	  const props = useThemeProps({
	    props: inProps,
	    name: 'MuiToolbar'
	  });
	  const {
	      className,
	      component = 'div',
	      disableGutters = false,
	      variant = 'regular'
	    } = props,
	    other = _objectWithoutPropertiesLoose(props, _excluded);
	  const ownerState = _extends$1({}, props, {
	    component,
	    disableGutters,
	    variant
	  });
	  const classes = useUtilityClasses(ownerState);
	  return /*#__PURE__*/jsxRuntimeExports.jsx(ToolbarRoot, _extends$1({
	    as: component,
	    className: clsx(classes.root, className),
	    ref: ref,
	    ownerState: ownerState
	  }, other));
	});
	var Toolbar$1 = Toolbar;

	// Manager modules enabled in lemonldap-ng.ini (enabledModules): psgi.js lists
	// them in `links`, identified by their default route (e.g. "sessions.html").
	// Without psgi.js (dev server, tests), every module is considered enabled.
	function isModuleEnabled(target) {
	    var links = window.links;
	    if (!Array.isArray(links))
	        return true;
	    return links.some(function (l) { return l.target === target; });
	}

	// URLs of the manager API and static files, built from the globals defined
	// by psgi.js: the manager is not always served at the root (e.g.
	// /manager.psgi/). Both scriptname and staticPrefix end with "/".
	var staticUrl = function (path) {
	    return "".concat(window.staticPrefix || "/static/").concat(path);
	};

	// Each manager section is a separate SPA (separate HTML page + bundle).
	// Navigating between them is a full page load, like the legacy manager.
	// Items without a `target` are placeholders not implemented yet.
	// `target` is the default route of the matching manager module.
	var NAV_ITEMS = [
	    {
	        key: "Configuration",
	        icon: jsxRuntimeExports.jsx(SettingsOutlinedIcon, { fontSize: "small" }),
	        target: "manager.html",
	    },
	    {
	        key: "sessions",
	        icon: jsxRuntimeExports.jsx(GroupOutlinedIcon, { fontSize: "small" }),
	        target: "sessions.html",
	    },
	    {
	        key: "notifications",
	        icon: jsxRuntimeExports.jsx(NotificationsNoneOutlinedIcon, { fontSize: "small" }),
	        target: "notifications.html",
	    },
	    {
	        key: "secondFactors",
	        icon: jsxRuntimeExports.jsx(SecurityOutlinedIcon, { fontSize: "small" }),
	        target: "2ndfa.html",
	    },
	];
	// Only show the sections whose module is enabled. Enabled modules without a
	// new UI yet (viewer, api, custom) are not shown.
	var enabledNavItems = function () {
	    return NAV_ITEMS.filter(function (item) { return item.target && isModuleEnabled(item.target); });
	};
	// The global nav lives in a top AppBar; `open`/`toggleNavbar` now only drive
	// the temporary Drawer used on narrow screens (< ~950px) to hold the section
	// links, instead of the old wide/narrow persistent left rail. Per-app pages
	// keep their own `.optionNavbar` left column, so we don't want a second
	// permanent left rail from the global nav.
	function Navbar(_a) {
	    var htmlName = _a.htmlName, open = _a.open, toggleNavbar = _a.toggleNavbar;
	    var t = useTranslation().t;
	    var partial = htmlName == "partial.html";
	    var renderNavItems = function (closeDrawerOnClick) {
	        return enabledNavItems().map(function (item) {
	            var active = item.target === htmlName;
	            return (jsxRuntimeExports.jsxs("div", { className: "navItem" +
	                    (active ? " active" : "") +
	                    (item.target ? "" : " disabled"), onClick: function () {
	                    if (item.target)
	                        window.location.assign(item.target);
	                    if (closeDrawerOnClick)
	                        toggleNavbar();
	                }, children: [item.icon, jsxRuntimeExports.jsx("span", { children: t(item.key) })] }, item.key));
	        });
	    };
	    return (jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [jsxRuntimeExports.jsx(AppBar$1, { position: "sticky", color: "transparent", elevation: 0, className: "topNav", children: jsxRuntimeExports.jsxs(Toolbar$1, { className: "topNavToolbar", disableGutters: true, children: [jsxRuntimeExports.jsx("a", { className: "brandLink", href: partial ? undefined : window.scriptname || "./", children: jsxRuntimeExports.jsx("img", { className: "brandLogo", src: staticUrl("logos/llng-logo-32.png"), alt: "LemonLogo" }) }), !partial && (jsxRuntimeExports.jsxs("nav", { className: "navMenu navMenuDesktop", children: [renderNavItems(false), jsxRuntimeExports.jsx(LegacyUiSwitch, {})] })), jsxRuntimeExports.jsx("div", { className: "topNavSpacer" }), !partial && (jsxRuntimeExports.jsx(IconButton$1, { className: "navBurger", "aria-label": "open navigation menu", color: "inherit", onClick: function () { return toggleNavbar(); }, children: jsxRuntimeExports.jsx(MenuIcon, {}) })), jsxRuntimeExports.jsx(OptionMenu, {})] }) }), !partial && (jsxRuntimeExports.jsxs(Drawer$1, { className: "navDrawerMobile", anchor: "left", open: open, onClose: function () { return toggleNavbar(); }, children: [jsxRuntimeExports.jsx("div", { className: "navDrawerHeader", children: jsxRuntimeExports.jsx(IconButton$1, { "aria-label": "close navigation menu", onClick: function () { return toggleNavbar(); }, children: jsxRuntimeExports.jsx(ChevronLeft, {}) }) }), jsxRuntimeExports.jsxs("nav", { className: "navMenu", children: [renderNavItems(true), jsxRuntimeExports.jsx(LegacyUiSwitch, {})] })] }))] }));
	}
	// Leave the beta interface: dropping the cookie sends the user back to the
	// historical manager, which is served by the same routes.
	function LegacyUiSwitch() {
	    var t = useTranslation().t;
	    return (jsxRuntimeExports.jsxs("div", { className: "navItem legacyUiSwitch", onClick: function () {
	            // Clear at the canonical path and at the current directory, to also
	            // drop a cookie left over at another path by an earlier session
	            for (var _i = 0, _a = ["/", location.pathname.replace(/[^/]*$/, "")]; _i < _a.length; _i++) {
	                var path = _a[_i];
	                document.cookie = "llngmanagerbeta=; path=".concat(path, "; SameSite=Lax; Max-Age=0; expires=Thu, 01 Jan 1970 00:00:00 GMT");
	            }
	            window.location.reload();
	        }, children: [jsxRuntimeExports.jsx(ChevronLeft, { fontSize: "small" }), jsxRuntimeExports.jsx("span", { children: t("backToLegacyManager") })] }));
	}
	function OptionMenu() {
	    var t = useTranslation().t;
	    var _a = reactExports.useState(false), menuOpen = _a[0], setMenuOpen = _a[1];
	    var handleLanguageChange = function (language) {
	        instance.changeLanguage(language);
	        console.debug("Language changed to ".concat(language));
	    };
	    var _b = reactExports.useState(null), anchorEl = _b[0], setAnchorEl = _b[1];
	    return (jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [jsxRuntimeExports.jsx(IconButton$1, { edge: "end", className: "menuBurger", "aria-label": "menu burger", "aria-controls": "menu-appbar", "aria-haspopup": "true", onClick: function (e) {
	                    setMenuOpen(true);
	                    setAnchorEl(e.currentTarget);
	                }, color: "inherit", children: jsxRuntimeExports.jsx(MenuIcon, {}) }), jsxRuntimeExports.jsxs(Menu$1, { id: "menu-appbar", anchorEl: anchorEl, keepMounted: true, anchorOrigin: {
	                    vertical: "bottom",
	                    horizontal: "right",
	                }, transformOrigin: {
	                    vertical: "top",
	                    horizontal: "right",
	                }, open: menuOpen, onClose: function () { return setMenuOpen(false); }, children: [jsxRuntimeExports.jsx(MenuItem$1, { onClick: function () {
	                            window.menulinks.map(function (el) {
	                                if (el.title === "backtoportal") {
	                                    window.location.assign(el.target);
	                                }
	                            });
	                        }, children: t("backtoportal") }), jsxRuntimeExports.jsx(MenuItem$1, { onClick: function () {
	                            window.menulinks.map(function (el) {
	                                if (el.title === "logout") {
	                                    window.location.assign(el.target);
	                                }
	                            });
	                        }, children: t("logout") }), jsxRuntimeExports.jsx(Divider$1, {}), jsxRuntimeExports.jsx(MenuItem$1, { disableRipple: true, children: jsxRuntimeExports.jsx(ButtonGroup$1, { variant: "text", color: "secondary", "aria-label": "language selection", sx: { flexWrap: "wrap" }, children: (window
	                                .availableLanguages || []).map(function (lang) {
	                                return (jsxRuntimeExports.jsx(Button$1, { onClick: function () { return handleLanguageChange(lang); }, title: lang, sx: { minWidth: 0, px: 0.5, py: 0.25 }, children: jsxRuntimeExports.jsx("img", { src: "".concat(window.staticPrefix || "/static/", "logos/").concat(lang, ".png"), alt: lang, width: 20, height: 14 }) }, lang));
	                            }) }) }), jsxRuntimeExports.jsx(Divider$1, {}), jsxRuntimeExports.jsxs(MenuItem$1, { children: [t("version"), " 0.0.1"] })] })] }));
	}

	var HourglassEmpty = {};

	var hasRequiredHourglassEmpty;

	function requireHourglassEmpty () {
		if (hasRequiredHourglassEmpty) return HourglassEmpty;
		hasRequiredHourglassEmpty = 1;

		var _interopRequireDefault = requireInteropRequireDefault();
		Object.defineProperty(HourglassEmpty, "__esModule", {
		  value: true
		});
		HourglassEmpty.default = void 0;
		var _createSvgIcon = _interopRequireDefault(/*@__PURE__*/ requireCreateSvgIcon());
		var _jsxRuntime = requireJsxRuntime();
		HourglassEmpty.default = (0, _createSvgIcon.default)(/*#__PURE__*/(0, _jsxRuntime.jsx)("path", {
		  d: "M6 2v6h.01L6 8.01 10 12l-4 4 .01.01H6V22h12v-5.99h-.01L18 16l-4-4 4-3.99-.01-.01H18V2zm10 14.5V20H8v-3.5l4-4zm-4-5-4-4V4h8v3.5z"
		}), 'HourglassEmpty');
		return HourglassEmpty;
	}

	var HourglassEmptyExports = /*@__PURE__*/ requireHourglassEmpty();
	var HourglassEmptyIcon = /*@__PURE__*/getDefaultExportFromCjs(HourglassEmptyExports);

	var LockOutlined = {};

	var hasRequiredLockOutlined;

	function requireLockOutlined () {
		if (hasRequiredLockOutlined) return LockOutlined;
		hasRequiredLockOutlined = 1;

		var _interopRequireDefault = requireInteropRequireDefault();
		Object.defineProperty(LockOutlined, "__esModule", {
		  value: true
		});
		LockOutlined.default = void 0;
		var _createSvgIcon = _interopRequireDefault(/*@__PURE__*/ requireCreateSvgIcon());
		var _jsxRuntime = requireJsxRuntime();
		LockOutlined.default = (0, _createSvgIcon.default)(/*#__PURE__*/(0, _jsxRuntime.jsx)("path", {
		  d: "M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2M9 6c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9zm9 14H6V10h12zm-6-3c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2"
		}), 'LockOutlined');
		return LockOutlined;
	}

	var LockOutlinedExports = /*@__PURE__*/ requireLockOutlined();
	var LockOutlinedIcon = /*@__PURE__*/getDefaultExportFromCjs(LockOutlinedExports);

	var PersonOutline = {};

	var hasRequiredPersonOutline;

	function requirePersonOutline () {
		if (hasRequiredPersonOutline) return PersonOutline;
		hasRequiredPersonOutline = 1;

		var _interopRequireDefault = requireInteropRequireDefault();
		Object.defineProperty(PersonOutline, "__esModule", {
		  value: true
		});
		PersonOutline.default = void 0;
		var _createSvgIcon = _interopRequireDefault(/*@__PURE__*/ requireCreateSvgIcon());
		var _jsxRuntime = requireJsxRuntime();
		PersonOutline.default = (0, _createSvgIcon.default)(/*#__PURE__*/(0, _jsxRuntime.jsx)("path", {
		  d: "M12 5.9c1.16 0 2.1.94 2.1 2.1s-.94 2.1-2.1 2.1S9.9 9.16 9.9 8s.94-2.1 2.1-2.1m0 9c2.97 0 6.1 1.46 6.1 2.1v1.1H5.9V17c0-.64 3.13-2.1 6.1-2.1M12 4C9.79 4 8 5.79 8 8s1.79 4 4 4 4-1.79 4-4-1.79-4-4-4m0 9c-2.67 0-8 1.34-8 4v3h16v-3c0-2.66-5.33-4-8-4"
		}), 'PersonOutline');
		return PersonOutline;
	}

	var PersonOutlineExports = /*@__PURE__*/ requirePersonOutline();
	var PersonOutlineIcon = /*@__PURE__*/getDefaultExportFromCjs(PersonOutlineExports);

	var Public = {};

	var hasRequiredPublic;

	function requirePublic () {
		if (hasRequiredPublic) return Public;
		hasRequiredPublic = 1;

		var _interopRequireDefault = requireInteropRequireDefault();
		Object.defineProperty(Public, "__esModule", {
		  value: true
		});
		Public.default = void 0;
		var _createSvgIcon = _interopRequireDefault(/*@__PURE__*/ requireCreateSvgIcon());
		var _jsxRuntime = requireJsxRuntime();
		Public.default = (0, _createSvgIcon.default)(/*#__PURE__*/(0, _jsxRuntime.jsx)("path", {
		  d: "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2m-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39"
		}), 'Public');
		return Public;
	}

	var PublicExports = /*@__PURE__*/ requirePublic();
	var PublicIcon = /*@__PURE__*/getDefaultExportFromCjs(PublicExports);

	var ReportProblemOutlined = {};

	var hasRequiredReportProblemOutlined;

	function requireReportProblemOutlined () {
		if (hasRequiredReportProblemOutlined) return ReportProblemOutlined;
		hasRequiredReportProblemOutlined = 1;

		var _interopRequireDefault = requireInteropRequireDefault();
		Object.defineProperty(ReportProblemOutlined, "__esModule", {
		  value: true
		});
		ReportProblemOutlined.default = void 0;
		var _createSvgIcon = _interopRequireDefault(/*@__PURE__*/ requireCreateSvgIcon());
		var _jsxRuntime = requireJsxRuntime();
		ReportProblemOutlined.default = (0, _createSvgIcon.default)(/*#__PURE__*/(0, _jsxRuntime.jsx)("path", {
		  d: "M12 5.99 19.53 19H4.47zM12 2 1 21h22zm1 14h-2v2h2zm0-6h-2v4h2z"
		}), 'ReportProblemOutlined');
		return ReportProblemOutlined;
	}

	var ReportProblemOutlinedExports = /*@__PURE__*/ requireReportProblemOutlined();
	var ReportProblemOutlinedIcon = /*@__PURE__*/getDefaultExportFromCjs(ReportProblemOutlinedExports);

	var Schedule = {};

	var hasRequiredSchedule;

	function requireSchedule () {
		if (hasRequiredSchedule) return Schedule;
		hasRequiredSchedule = 1;

		var _interopRequireDefault = requireInteropRequireDefault();
		Object.defineProperty(Schedule, "__esModule", {
		  value: true
		});
		Schedule.default = void 0;
		var _createSvgIcon = _interopRequireDefault(/*@__PURE__*/ requireCreateSvgIcon());
		var _jsxRuntime = requireJsxRuntime();
		Schedule.default = (0, _createSvgIcon.default)([/*#__PURE__*/(0, _jsxRuntime.jsx)("path", {
		  d: "M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2M12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8"
		}, "0"), /*#__PURE__*/(0, _jsxRuntime.jsx)("path", {
		  d: "M12.5 7H11v6l5.25 3.15.75-1.23-4.5-2.67z"
		}, "1")], 'Schedule');
		return Schedule;
	}

	var ScheduleExports = /*@__PURE__*/ requireSchedule();
	var ScheduleIcon = /*@__PURE__*/getDefaultExportFromCjs(ScheduleExports);

	var Update = {};

	var hasRequiredUpdate;

	function requireUpdate () {
		if (hasRequiredUpdate) return Update;
		hasRequiredUpdate = 1;

		var _interopRequireDefault = requireInteropRequireDefault();
		Object.defineProperty(Update, "__esModule", {
		  value: true
		});
		Update.default = void 0;
		var _createSvgIcon = _interopRequireDefault(/*@__PURE__*/ requireCreateSvgIcon());
		var _jsxRuntime = requireJsxRuntime();
		Update.default = (0, _createSvgIcon.default)(/*#__PURE__*/(0, _jsxRuntime.jsx)("path", {
		  d: "M21 10.12h-6.78l2.74-2.82c-2.73-2.7-7.15-2.8-9.88-.1-2.73 2.71-2.73 7.08 0 9.79s7.15 2.71 9.88 0C18.32 15.65 19 14.08 19 12.1h2c0 1.98-.88 4.55-2.64 6.29-3.51 3.48-9.21 3.48-12.72 0-3.5-3.47-3.53-9.11-.02-12.58s9.14-3.47 12.65 0L21 3zM12.5 8v4.25l3.5 2.08-.72 1.21L11 13V8z"
		}), 'Update');
		return Update;
	}

	var UpdateExports = /*@__PURE__*/ requireUpdate();
	var UpdateIcon = /*@__PURE__*/getDefaultExportFromCjs(UpdateExports);

	var Delete = {};

	var hasRequiredDelete;

	function requireDelete () {
		if (hasRequiredDelete) return Delete;
		hasRequiredDelete = 1;

		var _interopRequireDefault = requireInteropRequireDefault();
		Object.defineProperty(Delete, "__esModule", {
		  value: true
		});
		Delete.default = void 0;
		var _createSvgIcon = _interopRequireDefault(/*@__PURE__*/ requireCreateSvgIcon());
		var _jsxRuntime = requireJsxRuntime();
		Delete.default = (0, _createSvgIcon.default)(/*#__PURE__*/(0, _jsxRuntime.jsx)("path", {
		  d: "M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6zM19 4h-3.5l-1-1h-5l-1 1H5v2h14z"
		}), 'Delete');
		return Delete;
	}

	var DeleteExports = /*@__PURE__*/ requireDelete();
	var DeleteIcon = /*@__PURE__*/getDefaultExportFromCjs(DeleteExports);

	var Logout = {};

	var hasRequiredLogout;

	function requireLogout () {
		if (hasRequiredLogout) return Logout;
		hasRequiredLogout = 1;

		var _interopRequireDefault = requireInteropRequireDefault();
		Object.defineProperty(Logout, "__esModule", {
		  value: true
		});
		Logout.default = void 0;
		var _createSvgIcon = _interopRequireDefault(/*@__PURE__*/ requireCreateSvgIcon());
		var _jsxRuntime = requireJsxRuntime();
		Logout.default = (0, _createSvgIcon.default)(/*#__PURE__*/(0, _jsxRuntime.jsx)("path", {
		  d: "m17 7-1.41 1.41L18.17 11H8v2h10.17l-2.58 2.58L17 17l5-5zM4 5h8V3H4c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h8v-2H4z"
		}), 'Logout');
		return Logout;
	}

	var LogoutExports = /*@__PURE__*/ requireLogout();
	var LogoutIcon = /*@__PURE__*/getDefaultExportFromCjs(LogoutExports);

	// Session detail preparation — faithful port of `transformSession` and the
	// `categories` map from the legacy sessions.js. Turns a raw session hash into
	// ordered, translated groups of rows for the detail panel.
	// Attributes grouped in the detail view (order preserved).
	var categories = {
	    dateTitle: ["_utime", "_startTime", "_updateTime", "_lastAuthnUTime", "_lastSeen"],
	    connectionTitle: ["ipAddr", "_timezone", "_url"],
	    authenticationTitle: ["_session_id", "_user", "_password", "authenticationLevel"],
	    modulesTitle: [
	        "_auth",
	        "_userDB",
	        "_passwordDB",
	        "_issuerDB",
	        "_authChoice",
	        "_authMulti",
	        "_userDBMulti",
	        "_2f",
	    ],
	    saml: ["_idp", "_idpConfKey", "_samlToken", "_lassoSessionDump", "_lassoIdentityDump"],
	    groups: ["groups", "hGroups"],
	    ldap: ["dn"],
	    OpenIDConnect: [
	        "_oidc_id_token",
	        "_oidc_OP",
	        "_oidc_access_token",
	        "_oidc_refresh_token",
	        "_oidc_access_token_eol",
	        "_oidcConnectedRP",
	        "_oidcConnectedRPIDs",
	    ],
	    sfaTitle: ["_2fDevices"],
	    oidcConsents: ["_oidcConsents"],
	};
	function localeDate(s) {
	    if (!s && s !== 0)
	        return "";
	    var d = new Date(Number(s) * 1000);
	    return d.toLocaleString();
	}
	function strToLocaleDate(s) {
	    var m = String(s).match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/);
	    if (!m)
	        return String(s);
	    var d = new Date("".concat(m[1], "-").concat(m[2], "-").concat(m[3], "T").concat(m[4], ":").concat(m[5], ":").concat(m[6]));
	    return d.toLocaleString();
	}
	var impPrefix = function () { return window.impPrefix || "real_"; };
	function transformSession(raw) {
	    var session = __assign({}, raw);
	    var time = session._utime;
	    var res = [];
	    // 1. Normalize values: drop empty, split multivalued, format dates.
	    for (var _i = 0, _a = Object.keys(session); _i < _a.length; _i++) {
	        var key = _a[_i];
	        var value = session[key];
	        if (!value && value !== 0) {
	            delete session[key];
	            continue;
	        }
	        if (typeof value === "string" && value.match(/; /)) {
	            session[key] = value.split("; ");
	        }
	        if (typeof session[key] !== "object") {
	            if (key === "_password") {
	                session[key] = "********";
	            }
	            else if (key.match(/^(_utime|_lastAuthnUTime|_lastSeen|notification)$/)) {
	                session[key] = localeDate(value);
	            }
	            else if (key.match(/^(_startTime|_updateTime)$/)) {
	                session[key] = strToLocaleDate(value);
	            }
	        }
	    }
	    // 2. Grouped categories.
	    for (var _b = 0, _c = Object.keys(categories); _b < _c.length; _b++) {
	        var category = _c[_b];
	        var subres = [];
	        for (var _d = 0, _e = categories[category]; _d < _e.length; _d++) {
	            var attr = _e[_d];
	            var val = session[attr];
	            if (!val) {
	                delete session[attr];
	                continue;
	            }
	            if (attr === "_2fDevices") {
	                try {
	                    var devices = JSON.parse(val);
	                    if (Array.isArray(devices) && devices.length > 0) {
	                        subres.push({ title: "type", value: "name", epoch: "date", td: "0" });
	                        for (var _f = 0, devices_1 = devices; _f < devices_1.length; _f++) {
	                            var d = devices_1[_f];
	                            subres.push({
	                                title: d.type,
	                                value: d.name,
	                                epoch: d.epoch,
	                                td: "1",
	                            });
	                        }
	                    }
	                }
	                catch (e) {
	                    /* ignore malformed */
	                }
	                delete session[attr];
	            }
	            else if (val.toString().match(/"rp":\s*"[\w-]+"/)) {
	                subres.push({ title: "RP", value: "scope", epoch: "date", td: "0" });
	                try {
	                    var consents = JSON.parse(val);
	                    for (var _g = 0, consents_1 = consents; _g < consents_1.length; _g++) {
	                        var c = consents_1[_g];
	                        subres.push({
	                            title: c.rp,
	                            value: c.scope,
	                            epoch: c.epoch,
	                            td: "2",
	                        });
	                    }
	                }
	                catch (e) {
	                    /* ignore malformed */
	                }
	                delete session[attr];
	            }
	            else if (val.toString().match(/\w+/)) {
	                subres.push({ title: attr, value: session[attr], epoch: "" });
	                delete session[attr];
	            }
	            else {
	                delete session[attr];
	            }
	        }
	        if (subres.length > 0) {
	            res.push({ title: category, nodes: subres });
	        }
	    }
	    // 3. openid* and already-sent notifications, grouped and date-sorted.
	    var insert = function (re, title) {
	        var reg = new RegExp(re);
	        var collected = [];
	        for (var _i = 0, _a = Object.keys(session); _i < _a.length; _i++) {
	            var key = _a[_i];
	            var value = session[key];
	            if (key.match(reg) && value) {
	                collected.push({ key: key, date: value });
	                delete session[key];
	            }
	        }
	        if (collected.length) {
	            collected.sort(function (a, b) { return (a.key < b.key ? 1 : a.key > b.key ? -1 : 0); });
	            res.push({
	                title: title,
	                nodes: collected.map(function (c) { return ({
	                    title: c.key,
	                    value: localeDate(c.date),
	                }); }),
	            });
	        }
	    };
	    insert("^openid", "OpenID");
	    insert("^notification_(.+)", "notificationsDone");
	    // 4. Login history (success + failed), most recent first.
	    if (session._loginHistory) {
	        var rows_1 = [];
	        var collect = function (list, render) {
	            for (var _i = 0, _a = list || []; _i < _a.length; _i++) {
	                var l = _a[_i];
	                var cv = "";
	                for (var _b = 0, _c = Object.keys(l); _b < _c.length; _b++) {
	                    var key = _c[_b];
	                    if (!key.match(/^(_utime|ipAddr|error)$/))
	                        cv += ", ".concat(key, " : ").concat(l[key]);
	                }
	                cv = cv.split(", ").sort().join(", ");
	                rows_1.push({ t: l._utime, title: localeDate(l._utime), value: render(l, cv) });
	            }
	        };
	        collect(session._loginHistory.successLogin, function (l, cv) { return "Success (IP ".concat(l.ipAddr, ")") + cv; });
	        collect(session._loginHistory.failedLogin, function (l, cv) { return "Error ".concat(l.error, " (IP ").concat(l.ipAddr, ")") + cv; });
	        delete session._loginHistory;
	        rows_1.sort(function (a, b) { return b.t - a.t; });
	        res.push({ title: "loginHistory", nodes: rows_1 });
	    }
	    // 5. Remaining attributes and macros (spoofed first, real_ impersonation last).
	    var remaining = Object.keys(session).map(function (key) { return ({
	        title: key,
	        value: session[key],
	    }); });
	    remaining.sort(function (a, b) { return (a.title > b.title ? 1 : a.title < b.title ? -1 : 0); });
	    var realRe = new RegExp("^" + impPrefix() + ".+$");
	    var spoof = remaining.filter(function (r) { return !r.title.match(realRe); });
	    var real = remaining.filter(function (r) { return r.title.match(realRe); });
	    res.push({ title: "attributesAndMacros", nodes: spoof.concat(real) });
	    return { _utime: time, nodes: res };
	}
	// Format a grouping value into a tree node title (start/update time views).
	function formatTreeTitle(type, value) {
	    if (type.match(/^_?(start|update)Time$/i) || type === "_startTime" || type === "_updateTime") {
	        return String(value)
	            .replace(/^(\d{8})(\d{2})(\d{2})$/, "$2:$3")
	            .replace(/^(\d{8})(\d{2})(\d)$/, "$2:$30")
	            .replace(/^(\d{8})(\d{2})$/, "$2h")
	            .replace(/^(\d{4})(\d{2})(\d{2})/, "$1-$2-$3");
	    }
	    return String(value);
	}

	// REST client for the existing manager Sessions API (unchanged server side).
	// All paths are relative to `window.scriptname` (injected by psgi.js), exactly
	// like the legacy AngularJS explorer: `${scriptname}sessions/...`.
	var base = function () { return window.scriptname || "/"; };
	function toJson(res) {
	    return __awaiter(this, void 0, void 0, function () {
	        var text;
	        return __generator(this, function (_a) {
	            switch (_a.label) {
	                case 0: return [4 /*yield*/, res.text()];
	                case 1:
	                    text = _a.sent();
	                    try {
	                        return [2 /*return*/, text ? JSON.parse(text) : {}];
	                    }
	                    catch (e) {
	                        throw new Error(text || res.statusText);
	                    }
	                    return [2 /*return*/];
	            }
	        });
	    });
	}
	function listSessions(sessionType, query) {
	    return __awaiter(this, void 0, void 0, function () {
	        var res;
	        return __generator(this, function (_a) {
	            switch (_a.label) {
	                case 0: return [4 /*yield*/, fetch("".concat(base(), "sessions/").concat(sessionType, "?").concat(query), {
	                        credentials: "same-origin",
	                    })];
	                case 1:
	                    res = _a.sent();
	                    return [2 /*return*/, toJson(res)];
	            }
	        });
	    });
	}
	function getSession(sessionType, sessionId) {
	    return __awaiter(this, void 0, void 0, function () {
	        var res;
	        return __generator(this, function (_a) {
	            switch (_a.label) {
	                case 0: return [4 /*yield*/, fetch("".concat(base(), "sessions/").concat(sessionType, "/").concat(encodeURIComponent(sessionId)), { credentials: "same-origin" })];
	                case 1:
	                    res = _a.sent();
	                    return [2 /*return*/, toJson(res)];
	            }
	        });
	    });
	}
	function deleteSession(sessionType, sessionId) {
	    return __awaiter(this, void 0, void 0, function () {
	        var res;
	        return __generator(this, function (_a) {
	            switch (_a.label) {
	                case 0: return [4 /*yield*/, fetch("".concat(base(), "sessions/").concat(sessionType, "/").concat(encodeURIComponent(sessionId)), { method: "DELETE", credentials: "same-origin" })];
	                case 1:
	                    res = _a.sent();
	                    return [2 /*return*/, toJson(res)];
	            }
	        });
	    });
	}
	function globalLogout(sessionType, sessionId) {
	    return __awaiter(this, void 0, void 0, function () {
	        var res;
	        return __generator(this, function (_a) {
	            switch (_a.label) {
	                case 0: return [4 /*yield*/, fetch("".concat(base(), "sessions/glogout/").concat(sessionType, "/").concat(encodeURIComponent(sessionId)), { method: "POST", credentials: "same-origin" })];
	                case 1:
	                    res = _a.sent();
	                    return [2 /*return*/, toJson(res)];
	            }
	        });
	    });
	}
	function deleteOIDCConsent(sessionType, sessionId, rp, epoch) {
	    return __awaiter(this, void 0, void 0, function () {
	        var res;
	        return __generator(this, function (_a) {
	            switch (_a.label) {
	                case 0: return [4 /*yield*/, fetch("".concat(base(), "sessions/OIDCConsent/").concat(sessionType, "/").concat(encodeURIComponent(sessionId), "?rp=").concat(encodeURIComponent(rp), "&epoch=").concat(encodeURIComponent(String(epoch))), { method: "DELETE", credentials: "same-origin" })];
	                case 1:
	                    res = _a.sent();
	                    return [2 /*return*/, toJson(res)];
	            }
	        });
	    });
	}

	function renderValue(value) {
	    if (Array.isArray(value))
	        return value.join(", ");
	    if (value && typeof value === "object")
	        return JSON.stringify(value);
	    return String(value);
	}
	function SessionDetail(_a) {
	    var _this = this;
	    var sessionType = _a.sessionType, node = _a.node, onDeleted = _a.onDeleted;
	    var t = useTranslation().t;
	    var _b = reactExports.useState(null), detail = _b[0], setDetail = _b[1];
	    var _c = reactExports.useState(false), busy = _c[0], setBusy = _c[1];
	    var sessionId = node.session;
	    reactExports.useEffect(function () {
	        var cancelled = false;
	        setDetail(null);
	        getSession(sessionType, sessionId).then(function (raw) {
	            if (!cancelled)
	                setDetail(transformSession(raw));
	        });
	        return function () {
	            cancelled = true;
	        };
	    }, [sessionType, sessionId]);
	    var handleDelete = function () { return __awaiter(_this, void 0, void 0, function () {
	        return __generator(this, function (_a) {
	            switch (_a.label) {
	                case 0:
	                    setBusy(true);
	                    _a.label = 1;
	                case 1:
	                    _a.trys.push([1, , 3, 4]);
	                    return [4 /*yield*/, deleteSession(sessionType, sessionId)];
	                case 2:
	                    _a.sent();
	                    onDeleted(node.id);
	                    return [3 /*break*/, 4];
	                case 3:
	                    setBusy(false);
	                    return [7 /*endfinally*/];
	                case 4: return [2 /*return*/];
	            }
	        });
	    }); };
	    var handleGlobalLogout = function () { return __awaiter(_this, void 0, void 0, function () {
	        return __generator(this, function (_a) {
	            switch (_a.label) {
	                case 0:
	                    setBusy(true);
	                    _a.label = 1;
	                case 1:
	                    _a.trys.push([1, , 3, 4]);
	                    return [4 /*yield*/, globalLogout(sessionType, sessionId)];
	                case 2:
	                    _a.sent();
	                    onDeleted(node.id);
	                    return [3 /*break*/, 4];
	                case 3:
	                    setBusy(false);
	                    return [7 /*endfinally*/];
	                case 4: return [2 /*return*/];
	            }
	        });
	    }); };
	    var handleConsentDelete = function (rp, epoch) { return __awaiter(_this, void 0, void 0, function () {
	        var raw;
	        return __generator(this, function (_a) {
	            switch (_a.label) {
	                case 0: return [4 /*yield*/, deleteOIDCConsent(sessionType, sessionId, rp, epoch)];
	                case 1:
	                    _a.sent();
	                    return [4 /*yield*/, getSession(sessionType, sessionId)];
	                case 2:
	                    raw = _a.sent();
	                    setDetail(transformSession(raw));
	                    return [2 /*return*/];
	            }
	        });
	    }); };
	    if (!detail) {
	        return jsxRuntimeExports.jsx("div", { className: "sessionDetail", children: t("waitingForDatas") });
	    }
	    var renderRow = function (group, row, index) {
	        // Header row of a 2FA-devices / OIDC-consents table.
	        if (row.td === "0") {
	            return (jsxRuntimeExports.jsxs("tr", { className: "attrHeader", children: [jsxRuntimeExports.jsx("th", { children: row.title }), jsxRuntimeExports.jsx("th", { children: row.value }), jsxRuntimeExports.jsx("th", { children: row.epoch }), jsxRuntimeExports.jsx("th", {})] }, index));
	        }
	        // 2FA device.
	        if (row.td === "1") {
	            return (jsxRuntimeExports.jsxs("tr", { children: [jsxRuntimeExports.jsx("td", { children: t(row.title, row.title) }), jsxRuntimeExports.jsx("td", { children: renderValue(row.value) }), jsxRuntimeExports.jsx("td", { children: localeDate(row.epoch) }), jsxRuntimeExports.jsx("td", {})] }, index));
	        }
	        // OIDC consent (deletable).
	        if (row.td === "2") {
	            return (jsxRuntimeExports.jsxs("tr", { children: [jsxRuntimeExports.jsx("td", { children: row.title }), jsxRuntimeExports.jsx("td", { children: renderValue(row.value) }), jsxRuntimeExports.jsx("td", { children: localeDate(row.epoch) }), jsxRuntimeExports.jsx("td", { children: jsxRuntimeExports.jsx(Button$1, { size: "small", color: "error", onClick: function () { var _a; return handleConsentDelete(row.title, (_a = row.epoch) !== null && _a !== void 0 ? _a : ""); }, children: t("delete") }) })] }, index));
	        }
	        // Regular attribute / login-history row.
	        return (jsxRuntimeExports.jsxs("tr", { children: [jsxRuntimeExports.jsx("th", { children: t(row.title, row.title) }), jsxRuntimeExports.jsx("td", { colSpan: 3, children: renderValue(row.value) })] }, index));
	    };
	    return (jsxRuntimeExports.jsxs("div", { className: "sessionDetail", children: [jsxRuntimeExports.jsxs("div", { className: "sessionDetailToolbar", children: [jsxRuntimeExports.jsx(Button$1, { variant: "contained", color: "error", size: "small", startIcon: jsxRuntimeExports.jsx(DeleteIcon, {}), disabled: busy, onClick: handleDelete, children: t("deleteSession") }), jsxRuntimeExports.jsx(Button$1, { variant: "outlined", color: "error", size: "small", startIcon: jsxRuntimeExports.jsx(LogoutIcon, {}), disabled: busy, onClick: handleGlobalLogout, children: t("globalLogout") })] }), detail.nodes.map(function (group) { return (jsxRuntimeExports.jsxs("div", { className: "sessionGroupBox", children: [jsxRuntimeExports.jsx("div", { className: "sessionGroupHeader", children: t(group.title, group.title) }), jsxRuntimeExports.jsx("table", { className: "sessionAttrTable", children: jsxRuntimeExports.jsx("tbody", { children: group.nodes.map(function (row, i) { return renderRow(group, row, i); }) }) })] }, group.title)); })] }));
	}

	var ChevronRight = {};

	var hasRequiredChevronRight;

	function requireChevronRight () {
		if (hasRequiredChevronRight) return ChevronRight;
		hasRequiredChevronRight = 1;

		var _interopRequireDefault = requireInteropRequireDefault();
		Object.defineProperty(ChevronRight, "__esModule", {
		  value: true
		});
		ChevronRight.default = void 0;
		var _createSvgIcon = _interopRequireDefault(/*@__PURE__*/ requireCreateSvgIcon());
		var _jsxRuntime = requireJsxRuntime();
		ChevronRight.default = (0, _createSvgIcon.default)(/*#__PURE__*/(0, _jsxRuntime.jsx)("path", {
		  d: "M10 6 8.59 7.41 13.17 12l-4.58 4.59L10 18l6-6z"
		}), 'ChevronRight');
		return ChevronRight;
	}

	var ChevronRightExports = /*@__PURE__*/ requireChevronRight();
	var ChevronRightIcon = /*@__PURE__*/getDefaultExportFromCjs(ChevronRightExports);

	var ExpandMore = {};

	var hasRequiredExpandMore;

	function requireExpandMore () {
		if (hasRequiredExpandMore) return ExpandMore;
		hasRequiredExpandMore = 1;

		var _interopRequireDefault = requireInteropRequireDefault();
		Object.defineProperty(ExpandMore, "__esModule", {
		  value: true
		});
		ExpandMore.default = void 0;
		var _createSvgIcon = _interopRequireDefault(/*@__PURE__*/ requireCreateSvgIcon());
		var _jsxRuntime = requireJsxRuntime();
		ExpandMore.default = (0, _createSvgIcon.default)(/*#__PURE__*/(0, _jsxRuntime.jsx)("path", {
		  d: "M16.59 8.59 12 13.17 7.41 8.59 6 10l6 6 6-6z"
		}), 'ExpandMore');
		return ExpandMore;
	}

	var ExpandMoreExports = /*@__PURE__*/ requireExpandMore();
	var ExpandMoreIcon = /*@__PURE__*/getDefaultExportFromCjs(ExpandMoreExports);

	var Visibility = {};

	var hasRequiredVisibility;

	function requireVisibility () {
		if (hasRequiredVisibility) return Visibility;
		hasRequiredVisibility = 1;

		var _interopRequireDefault = requireInteropRequireDefault();
		Object.defineProperty(Visibility, "__esModule", {
		  value: true
		});
		Visibility.default = void 0;
		var _createSvgIcon = _interopRequireDefault(/*@__PURE__*/ requireCreateSvgIcon());
		var _jsxRuntime = requireJsxRuntime();
		Visibility.default = (0, _createSvgIcon.default)(/*#__PURE__*/(0, _jsxRuntime.jsx)("path", {
		  d: "M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5M12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5m0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3"
		}), 'Visibility');
		return Visibility;
	}

	var VisibilityExports = /*@__PURE__*/ requireVisibility();
	var VisibilityIcon = /*@__PURE__*/getDefaultExportFromCjs(VisibilityExports);

	// Progressive discovery of sessions — faithful port of the legacy
	// `schemes` / `overScheme` from lemonldap-ng-manager/site/js-src/sessions.js.
	//
	// Each `schemes[type]` is an array of query builders, one per tree depth.
	// Expanding a node runs `schemes[type][level](type, value, currentQuery)` to
	// build the `sessions/<type>?<query>` request. When a node returns more than
	// `MAX` children, `overScheme[type]` inserts an extra intermediate level so
	// the user drills down instead of facing a huge flat list.
	// Max number of sessions displayed before an extra grouping level is added.
	var MAX = 25;
	var schemes = {
	    _whatToTrace: [
	        // First level: group by first letter
	        function (t) { return "groupBy=substr(".concat(t, ",1)"); },
	        // Second level (if no overScheme): usernames
	        function (t, v) { return "".concat(t, "=").concat(v, "*&groupBy=").concat(t); },
	        function (t, v) { return "".concat(t, "=").concat(v); },
	    ],
	    ipAddr: [
	        function (t) { return "groupBy=net(".concat(t, ",16,1)"); },
	        function (t, v) {
	            if (!v.match(/:/))
	                v = v + ".";
	            return "".concat(t, "=").concat(v, "*&groupBy=net(").concat(t, ",32,2)");
	        },
	        function (t, v) {
	            if (!v.match(/:/))
	                v = v + ".";
	            return "".concat(t, "=").concat(v, "*&groupBy=net(").concat(t, ",48,3)");
	        },
	        function (t, v) {
	            if (!v.match(/:/))
	                v = v + ".";
	            return "".concat(t, "=").concat(v, "*&groupBy=net(").concat(t, ",128,4)");
	        },
	        function (t, v) { return "".concat(t, "=").concat(v, "&groupBy=_whatToTrace"); },
	        function (t, v, q) { return (q || "").replace(/&groupBy.*$/, "") + "&_whatToTrace=".concat(v); },
	    ],
	    _startTime: [
	        function (t) { return "groupBy=substr(".concat(t, ",8)"); },
	        function (t, v) { return "".concat(t, "=").concat(v, "*&groupBy=substr(").concat(t, ",10)"); },
	        function (t, v) { return "".concat(t, "=").concat(v, "*&groupBy=substr(").concat(t, ",11)"); },
	        function (t, v) { return "".concat(t, "=").concat(v, "*&groupBy=substr(").concat(t, ",12)"); },
	        function (t, v) { return "".concat(t, "=").concat(v, "*&groupBy=_whatToTrace"); },
	        function (t, v, q) { return (q || "").replace(/&groupBy.*$/, "") + "&_whatToTrace=".concat(v); },
	    ],
	    doubleIp: [
	        function (t) { return t; },
	        function (t, v) { return "_whatToTrace=".concat(v, "&groupBy=ipAddr"); },
	        function (t, v, q) { return (q || "").replace(/&groupBy.*$/, "") + "&ipAddr=".concat(v); },
	    ],
	    _session_uid: [
	        function (t) { return "groupBy=substr(".concat(t, ",1)"); },
	        function (t, v) { return "".concat(t, "=").concat(v, "*&groupBy=").concat(t); },
	        function (t, v) { return "".concat(t, "=").concat(v); },
	    ],
	};
	// When a node has more than MAX children and an overScheme is defined for its
	// type, an extra level is inserted (returns null to stop inserting).
	var overScheme = {
	    _whatToTrace: function (t, v, level, over) {
	        // "v.length >= (level+over)" avoids a loop when a single user opened more
	        // than MAX sessions.
	        if (v.length >= level + over)
	            return null;
	        if (level === 1 && v.length > over) {
	            return "".concat(t, "=").concat(v, "*&groupBy=substr(").concat(t, ",").concat(level + over + 1, ")");
	        }
	        return null;
	    },
	    // Note: IPv4 only
	    ipAddr: function (t, v, level, over) {
	        if (level > 0 && level < 4 && !v.match(/^\d+\.\d/) && over < 2) {
	            return "".concat(t, "=").concat(v, "*&groupBy=net(").concat(t, ",").concat(16 * level + 4 * (over + 1), ",").concat(1 + level + over, ")");
	        }
	        return null;
	    },
	    _startTime: function (t, v, level, over) {
	        if (level > 3) {
	            return "".concat(t, "=").concat(v, "*&groupBy=substr(").concat(t, ",").concat(10 + level + over, ")");
	        }
	        return null;
	    },
	    _session_uid: function (t, v, level, over) {
	        if (level === 1 && v.length > over) {
	            return "".concat(t, "=").concat(v, "*&groupBy=substr(").concat(t, ",").concat(level + over + 1, ")");
	        }
	        return null;
	    },
	};
	// Pick the query scheme for a session-view type (_updateTime reuses the
	// _startTime scheme, unknown types fall back to _whatToTrace).
	function schemeFor(type) {
	    if (schemes[type])
	        return schemes[type];
	    if (type === "_updateTime")
	        return schemes._startTime;
	    return schemes._whatToTrace;
	}

	var autoId = 0;
	var nextId = function () { return "node".concat(++autoId); };
	var ROOT_CONTEXT = {
	    value: "",
	    level: 0,
	    over: 0,
	};
	function loadChildren(type, sessionType, node) {
	    var _a;
	    return __awaiter(this, void 0, void 0, function () {
	        var scheme, level, over, query, tmp, data, children, _i, _b, v;
	        return __generator(this, function (_c) {
	            switch (_c.label) {
	                case 0:
	                    scheme = schemeFor(type);
	                    level = node.level;
	                    over = node.over;
	                    query = scheme[level](type, node.value, node.query);
	                    // Insert an extra level when a node has more than MAX children.
	                    if (node.count != null && node.count > MAX && overScheme[type]) {
	                        tmp = overScheme[type](type, node.value, level, over, node.query);
	                        if (tmp) {
	                            over++;
	                            query = tmp;
	                            level = level - 1;
	                        }
	                        else {
	                            over = 0;
	                        }
	                    }
	                    else {
	                        over = 0;
	                    }
	                    return [4 /*yield*/, listSessions(sessionType, query)];
	                case 1:
	                    data = _c.sent();
	                    children = [];
	                    if (data && data.result) {
	                        for (_i = 0, _b = data.values || []; _i < _b.length; _i++) {
	                            v = _b[_i];
	                            if (level < scheme.length - 1) {
	                                children.push({
	                                    id: nextId(),
	                                    isLeaf: false,
	                                    value: v.value,
	                                    count: v.count,
	                                    title: formatTreeTitle(type, (_a = v.value) !== null && _a !== void 0 ? _a : ""),
	                                    level: level + 1,
	                                    over: over,
	                                    query: query,
	                                });
	                            }
	                            else {
	                                children.push({
	                                    id: nextId(),
	                                    isLeaf: true,
	                                    session: v.session,
	                                    date: v.date,
	                                    level: level + 1,
	                                    over: over,
	                                });
	                            }
	                        }
	                    }
	                    return [2 /*return*/, { children: children, total: data ? data.total : 0 }];
	            }
	        });
	    });
	}

	function SessionTreeNode(_a) {
	    var _this = this;
	    var type = _a.type, sessionType = _a.sessionType, node = _a.node, depth = _a.depth, selectedId = _a.selectedId, onSelect = _a.onSelect, removedIds = _a.removedIds;
	    var _b = reactExports.useState(false), expanded = _b[0], setExpanded = _b[1];
	    var _c = reactExports.useState(null), children = _c[0], setChildren = _c[1];
	    var _d = reactExports.useState(false), loading = _d[0], setLoading = _d[1];
	    if (node.isLeaf) {
	        var selected = node.id === selectedId;
	        return (jsxRuntimeExports.jsxs("div", { className: "sessionLeaf" + (selected ? " selected" : ""), style: { paddingLeft: depth * 16 + 22 }, onClick: function () { return onSelect(node); }, children: [jsxRuntimeExports.jsx(VisibilityIcon, { fontSize: "inherit" }), jsxRuntimeExports.jsx("span", { children: localeDate(node.date) })] }));
	    }
	    var toggle = function () { return __awaiter(_this, void 0, void 0, function () {
	        var ch;
	        var _a;
	        return __generator(this, function (_b) {
	            switch (_b.label) {
	                case 0:
	                    if (!(!expanded && children === null)) return [3 /*break*/, 4];
	                    setLoading(true);
	                    _b.label = 1;
	                case 1:
	                    _b.trys.push([1, , 3, 4]);
	                    return [4 /*yield*/, loadChildren(type, sessionType, {
	                            value: (_a = node.value) !== null && _a !== void 0 ? _a : "",
	                            level: node.level,
	                            over: node.over,
	                            query: node.query,
	                            count: node.count,
	                        })];
	                case 2:
	                    ch = (_b.sent()).children;
	                    setChildren(ch);
	                    return [3 /*break*/, 4];
	                case 3:
	                    setLoading(false);
	                    return [7 /*endfinally*/];
	                case 4:
	                    setExpanded(!expanded);
	                    return [2 /*return*/];
	            }
	        });
	    }); };
	    var visibleChildren = (children || []).filter(function (c) { return !removedIds.has(c.id); });
	    return (jsxRuntimeExports.jsxs("div", { children: [jsxRuntimeExports.jsxs("div", { className: "sessionGroup", style: { paddingLeft: depth * 16 }, onClick: toggle, children: [expanded ? (jsxRuntimeExports.jsx(ExpandMoreIcon, { fontSize: "small" })) : (jsxRuntimeExports.jsx(ChevronRightIcon, { fontSize: "small" })), jsxRuntimeExports.jsx("span", { className: "sessionGroupTitle", children: node.title || node.value }), node.count != null && (jsxRuntimeExports.jsx(Chip$1, { size: "small", label: node.count, className: "sessionCount" })), loading && jsxRuntimeExports.jsx(CircularProgress$1, { size: 12, sx: { ml: 1 } })] }), expanded &&
	                visibleChildren.map(function (c) { return (jsxRuntimeExports.jsx(SessionTreeNode, { type: type, sessionType: sessionType, node: c, depth: depth + 1, selectedId: selectedId, onSelect: onSelect, removedIds: removedIds }, c.id)); })] }));
	}

	function hashView(hash) {
	    var m = hash.match(/#?!?\/(\w+)/);
	    if (!m)
	        return { type: "_whatToTrace", sessionType: "global" };
	    if (m[1] === "persistent" || m[1] === "offline") {
	        return { type: "_session_uid", sessionType: m[1] };
	    }
	    return { type: m[1], sessionType: "global" };
	}
	// Left-navigation entries (mirror the legacy sessions.tpl dropdown + links).
	var SSO_SUBVIEWS = [
	    { key: "users", hash: "", icon: jsxRuntimeExports.jsx(PersonOutlineIcon, { fontSize: "small" }) },
	    { key: "ipAddresses", hash: "!/ipAddr", icon: jsxRuntimeExports.jsx(PublicIcon, { fontSize: "small" }) },
	    { key: "multiIp", hash: "!/doubleIp", icon: jsxRuntimeExports.jsx(ReportProblemOutlinedIcon, { fontSize: "small" }) },
	    { key: "_startTime", hash: "!/_startTime", icon: jsxRuntimeExports.jsx(ScheduleIcon, { fontSize: "small" }) },
	    { key: "_updateTime", hash: "!/_updateTime", icon: jsxRuntimeExports.jsx(UpdateIcon, { fontSize: "small" }) },
	];
	var TOP_VIEWS = [
	    { key: "persistentSessions", hash: "!/persistent", icon: jsxRuntimeExports.jsx(LockOutlinedIcon, { fontSize: "small" }) },
	    { key: "offlineSessions", hash: "!/offline", icon: jsxRuntimeExports.jsx(HourglassEmptyIcon, { fontSize: "small" }) },
	];
	function SessionsExplorer() {
	    var t = useTranslation().t;
	    var _a = reactExports.useState(function () { return hashView(window.location.hash); }), view = _a[0], setView = _a[1];
	    var _b = reactExports.useState(null), rootChildren = _b[0], setRootChildren = _b[1];
	    var _c = reactExports.useState(0), total = _c[0], setTotal = _c[1];
	    var _d = reactExports.useState(null), selected = _d[0], setSelected = _d[1];
	    var _e = reactExports.useState(new Set()), removedIds = _e[0], setRemovedIds = _e[1];
	    var _f = reactExports.useState(false), loading = _f[0], setLoading = _f[1];
	    reactExports.useEffect(function () {
	        var onHash = function () { return setView(hashView(window.location.hash)); };
	        window.addEventListener("hashchange", onHash);
	        return function () { return window.removeEventListener("hashchange", onHash); };
	    }, []);
	    reactExports.useEffect(function () {
	        var cancelled = false;
	        setLoading(true);
	        setRootChildren(null);
	        setSelected(null);
	        setRemovedIds(new Set());
	        loadChildren(view.type, view.sessionType, ROOT_CONTEXT)
	            .then(function (_a) {
	            var children = _a.children, total = _a.total;
	            if (!cancelled) {
	                setRootChildren(children);
	                setTotal(total);
	                setLoading(false);
	            }
	        })
	            .catch(function () {
	            if (!cancelled) {
	                setRootChildren([]);
	                setLoading(false);
	            }
	        });
	        return function () {
	            cancelled = true;
	        };
	    }, [view.type, view.sessionType]);
	    var go = function (hash) {
	        window.location.hash = hash;
	    };
	    var isActive = function (hash) {
	        var v = hashView(hash);
	        return v.type === view.type && v.sessionType === view.sessionType;
	    };
	    var removeNode = function (id) {
	        setRemovedIds(function (s) { return new Set(s).add(id); });
	        setSelected(null);
	    };
	    var visibleRoot = (rootChildren || []).filter(function (c) { return !removedIds.has(c.id); });
	    var navItem = function (entry, sub) { return (jsxRuntimeExports.jsxs("div", { className: "sessionNavItem" +
	            (sub ? " sub" : "") +
	            (isActive(entry.hash) ? " active" : ""), onClick: function () { return go(entry.hash); }, children: [entry.icon, jsxRuntimeExports.jsx("span", { children: t(entry.key) })] }, entry.key)); };
	    return (jsxRuntimeExports.jsxs("div", { className: "sessionsExplorer", children: [jsxRuntimeExports.jsxs("aside", { className: "sessionsNav", children: [jsxRuntimeExports.jsxs("div", { className: "sessionNavGroup", children: [jsxRuntimeExports.jsxs("div", { className: "sessionNavHeader", children: [jsxRuntimeExports.jsx(GroupOutlinedIcon, { fontSize: "small" }), jsxRuntimeExports.jsx("span", { children: t("ssoSessions") })] }), SSO_SUBVIEWS.map(function (e) { return navItem(e, true); })] }), TOP_VIEWS.map(function (e) { return navItem(e, false); })] }), jsxRuntimeExports.jsxs("section", { className: "sessionsTree", children: [jsxRuntimeExports.jsxs("div", { className: "sessionsTreeHeader", children: [jsxRuntimeExports.jsx("strong", { children: t("sessions") }), jsxRuntimeExports.jsx(Chip$1, { size: "small", label: total }), loading && jsxRuntimeExports.jsx(CircularProgress$1, { size: 16 })] }), jsxRuntimeExports.jsxs("div", { className: "sessionsTreeBody", children: [visibleRoot.map(function (node) { return (jsxRuntimeExports.jsx(SessionTreeNode, { type: view.type, sessionType: view.sessionType, node: node, depth: 0, selectedId: selected ? selected.id : null, onSelect: setSelected, removedIds: removedIds }, node.id)); }), !loading && visibleRoot.length === 0 && (jsxRuntimeExports.jsx("div", { className: "sessionsEmpty", children: t("noSession") || "—" }))] })] }), jsxRuntimeExports.jsx("section", { className: "sessionsDetailPane", children: selected ? (jsxRuntimeExports.jsx(SessionDetail, { sessionType: view.sessionType, node: selected, onDeleted: removeNode })) : (jsxRuntimeExports.jsx("div", { className: "sessionsDetailPlaceholder", children: t("clickToDisplay") })) })] }));
	}

	function SessionsApp(_a) {
	    var htmlName = _a.htmlName;
	    useTranslation();
	    // `open` only drives the mobile section-links drawer (see Navbar).
	    var _b = reactExports.useState(false), open = _b[0], setOpen = _b[1];
	    return (jsxRuntimeExports.jsxs(reactExports.Suspense, { fallback: "loading", children: [jsxRuntimeExports.jsx(Navbar, { htmlName: htmlName, open: open, toggleNavbar: function () { return setOpen(!open); } }), jsxRuntimeExports.jsx("div", { className: "pageContent", children: jsxRuntimeExports.jsx(SessionsExplorer, {}) })] }));
	}

	mountApp(jsxRuntimeExports.jsx(SessionsApp, { htmlName: "sessions.html"  }));

	var e,
	  t,
	  n,
	  i,
	  r = function (e, t) {
	    return {
	      name: e,
	      value: void 0 === t ? -1 : t,
	      delta: 0,
	      entries: [],
	      id: "v2-".concat(Date.now(), "-").concat(Math.floor(8999999999999 * Math.random()) + 1e12)
	    };
	  },
	  a = function (e, t) {
	    try {
	      if (PerformanceObserver.supportedEntryTypes.includes(e)) {
	        if ("first-input" === e && !("PerformanceEventTiming" in self)) return;
	        var n = new PerformanceObserver(function (e) {
	          return e.getEntries().map(t);
	        });
	        return n.observe({
	          type: e,
	          buffered: !0
	        }), n;
	      }
	    } catch (e) {}
	  },
	  o = function (e, t) {
	    var n = function n(i) {
	      "pagehide" !== i.type && "hidden" !== document.visibilityState || (e(i), t && (removeEventListener("visibilitychange", n, !0), removeEventListener("pagehide", n, !0)));
	    };
	    addEventListener("visibilitychange", n, !0), addEventListener("pagehide", n, !0);
	  },
	  u = function (e) {
	    addEventListener("pageshow", function (t) {
	      t.persisted && e(t);
	    }, !0);
	  },
	  c = function (e, t, n) {
	    var i;
	    return function (r) {
	      t.value >= 0 && (r || n) && (t.delta = t.value - (i || 0), (t.delta || void 0 === i) && (i = t.value, e(t)));
	    };
	  },
	  f = -1,
	  s = function () {
	    return "hidden" === document.visibilityState ? 0 : 1 / 0;
	  },
	  m = function () {
	    o(function (e) {
	      var t = e.timeStamp;
	      f = t;
	    }, !0);
	  },
	  v = function () {
	    return f < 0 && (f = s(), m(), u(function () {
	      setTimeout(function () {
	        f = s(), m();
	      }, 0);
	    })), {
	      get firstHiddenTime() {
	        return f;
	      }
	    };
	  },
	  d = function (e, t) {
	    var n,
	      i = v(),
	      o = r("FCP"),
	      f = function (e) {
	        "first-contentful-paint" === e.name && (m && m.disconnect(), e.startTime < i.firstHiddenTime && (o.value = e.startTime, o.entries.push(e), n(!0)));
	      },
	      s = window.performance && performance.getEntriesByName && performance.getEntriesByName("first-contentful-paint")[0],
	      m = s ? null : a("paint", f);
	    (s || m) && (n = c(e, o, t), s && f(s), u(function (i) {
	      o = r("FCP"), n = c(e, o, t), requestAnimationFrame(function () {
	        requestAnimationFrame(function () {
	          o.value = performance.now() - i.timeStamp, n(!0);
	        });
	      });
	    }));
	  },
	  p = !1,
	  l = -1,
	  h = function (e, t) {
	    p || (d(function (e) {
	      l = e.value;
	    }), p = !0);
	    var n,
	      i = function (t) {
	        l > -1 && e(t);
	      },
	      f = r("CLS", 0),
	      s = 0,
	      m = [],
	      v = function (e) {
	        if (!e.hadRecentInput) {
	          var t = m[0],
	            i = m[m.length - 1];
	          s && e.startTime - i.startTime < 1e3 && e.startTime - t.startTime < 5e3 ? (s += e.value, m.push(e)) : (s = e.value, m = [e]), s > f.value && (f.value = s, f.entries = m, n());
	        }
	      },
	      h = a("layout-shift", v);
	    h && (n = c(i, f, t), o(function () {
	      h.takeRecords().map(v), n(!0);
	    }), u(function () {
	      s = 0, l = -1, f = r("CLS", 0), n = c(i, f, t);
	    }));
	  },
	  T = {
	    passive: !0,
	    capture: !0
	  },
	  y = new Date(),
	  g = function (i, r) {
	    e || (e = r, t = i, n = new Date(), w(removeEventListener), E());
	  },
	  E = function () {
	    if (t >= 0 && t < n - y) {
	      var r = {
	        entryType: "first-input",
	        name: e.type,
	        target: e.target,
	        cancelable: e.cancelable,
	        startTime: e.timeStamp,
	        processingStart: e.timeStamp + t
	      };
	      i.forEach(function (e) {
	        e(r);
	      }), i = [];
	    }
	  },
	  S = function (e) {
	    if (e.cancelable) {
	      var t = (e.timeStamp > 1e12 ? new Date() : performance.now()) - e.timeStamp;
	      "pointerdown" == e.type ? function (e, t) {
	        var n = function () {
	            g(e, t), r();
	          },
	          i = function () {
	            r();
	          },
	          r = function () {
	            removeEventListener("pointerup", n, T), removeEventListener("pointercancel", i, T);
	          };
	        addEventListener("pointerup", n, T), addEventListener("pointercancel", i, T);
	      }(t, e) : g(t, e);
	    }
	  },
	  w = function (e) {
	    ["mousedown", "keydown", "touchstart", "pointerdown"].forEach(function (t) {
	      return e(t, S, T);
	    });
	  },
	  L = function (n, f) {
	    var s,
	      m = v(),
	      d = r("FID"),
	      p = function (e) {
	        e.startTime < m.firstHiddenTime && (d.value = e.processingStart - e.startTime, d.entries.push(e), s(!0));
	      },
	      l = a("first-input", p);
	    s = c(n, d, f), l && o(function () {
	      l.takeRecords().map(p), l.disconnect();
	    }, !0), l && u(function () {
	      var a;
	      d = r("FID"), s = c(n, d, f), i = [], t = -1, e = null, w(addEventListener), a = p, i.push(a), E();
	    });
	  },
	  b = {},
	  F = function (e, t) {
	    var n,
	      i = v(),
	      f = r("LCP"),
	      s = function (e) {
	        var t = e.startTime;
	        t < i.firstHiddenTime && (f.value = t, f.entries.push(e), n());
	      },
	      m = a("largest-contentful-paint", s);
	    if (m) {
	      n = c(e, f, t);
	      var d = function () {
	        b[f.id] || (m.takeRecords().map(s), m.disconnect(), b[f.id] = !0, n(!0));
	      };
	      ["keydown", "click"].forEach(function (e) {
	        addEventListener(e, d, {
	          once: !0,
	          capture: !0
	        });
	      }), o(d, !0), u(function (i) {
	        f = r("LCP"), n = c(e, f, t), requestAnimationFrame(function () {
	          requestAnimationFrame(function () {
	            f.value = performance.now() - i.timeStamp, b[f.id] = !0, n(!0);
	          });
	        });
	      });
	    }
	  },
	  P = function (e) {
	    var t,
	      n = r("TTFB");
	    t = function () {
	      try {
	        var t = performance.getEntriesByType("navigation")[0] || function () {
	          var e = performance.timing,
	            t = {
	              entryType: "navigation",
	              startTime: 0
	            };
	          for (var n in e) "navigationStart" !== n && "toJSON" !== n && (t[n] = Math.max(e[n] - e.navigationStart, 0));
	          return t;
	        }();
	        if (n.value = n.delta = t.responseStart, n.value < 0 || n.value > performance.now()) return;
	        n.entries = [t], e(n);
	      } catch (e) {}
	    }, "complete" === document.readyState ? setTimeout(t, 0) : addEventListener("load", function () {
	      return setTimeout(t, 0);
	    });
	  };

	var webVitals = /*#__PURE__*/Object.freeze({
		__proto__: null,
		getCLS: h,
		getFCP: d,
		getFID: L,
		getLCP: F,
		getTTFB: P
	});

})();
