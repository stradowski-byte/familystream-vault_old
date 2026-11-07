/**
 * Copyright 2018 Google Inc. All Rights Reserved.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// If the loader is already loaded, just stop.
if (!self.define) {
  let registry = {};

  // Used for `eval` and `importScripts` where we can't get script URL by other means.
  // In both cases, it's safe to use a global var because those functions are synchronous.
  let nextDefineUri;

  const singleRequire = (uri, parentUri) => {
    uri = new URL(uri + ".js", parentUri).href;
    return registry[uri] || (
      
        new Promise(resolve => {
          if ("document" in self) {
            const script = document.createElement("script");
            script.src = uri;
            script.onload = resolve;
            document.head.appendChild(script);
          } else {
            nextDefineUri = uri;
            importScripts(uri);
            resolve();
          }
        })
      
      .then(() => {
        let promise = registry[uri];
        if (!promise) {
          throw new Error(`Module ${uri} didn’t register its module`);
        }
        return promise;
      })
    );
  };

  self.define = (depsNames, factory) => {
    const uri = nextDefineUri || ("document" in self ? document.currentScript.src : "") || location.href;
    if (registry[uri]) {
      // Module is already loading or loaded.
      return;
    }
    let exports = {};
    const require = depUri => singleRequire(depUri, uri);
    const specialDeps = {
      module: { uri },
      exports,
      require
    };
    registry[uri] = Promise.all(depsNames.map(
      depName => specialDeps[depName] || require(depName)
    )).then(deps => {
      factory(...deps);
      return exports;
    });
  };
}
define(['./workbox-7e5eb42b'], (function (workbox) { 'use strict';

  self.skipWaiting();
  workbox.clientsClaim();
  /**
   * The precacheAndRoute() method efficiently caches and responds to
   * requests for URLs in the manifest.
   * See https://goo.gl/S9QRab
   */
  workbox.precacheAndRoute([{
    "url": "registerSW.js",
    "revision": "402b66900e731ca748771b6fc5e7a068"
  }, {
    "url": "pwa-maskable-512x512.png",
    "revision": "53334bc832a48d6d2f4e9ccb0c00235f"
  }, {
    "url": "pwa-512x512.png",
    "revision": "42de683f0a7257869411ca42042fa544"
  }, {
    "url": "pwa-192x192.png",
    "revision": "9eb44ab79ac26af3c6295e0525d9adf8"
  }, {
    "url": "index.html",
    "revision": "74961b4f29268faa24059d6e79bf24ab"
  }, {
    "url": "icon.svg",
    "revision": "202d31dad24d64792ab945273f6275b3"
  }, {
    "url": "apple-touch-icon.png",
    "revision": "b1374edf5e4cf5bc54afaec5bf099be5"
  }, {
    "url": "assets/index-DD19ZZER.css",
    "revision": null
  }, {
    "url": "assets/index-Beg8FLbH.js",
    "revision": null
  }, {
    "url": "apple-touch-icon.png",
    "revision": "b1374edf5e4cf5bc54afaec5bf099be5"
  }, {
    "url": "icon.svg",
    "revision": "202d31dad24d64792ab945273f6275b3"
  }, {
    "url": "pwa-192x192.png",
    "revision": "9eb44ab79ac26af3c6295e0525d9adf8"
  }, {
    "url": "pwa-512x512.png",
    "revision": "42de683f0a7257869411ca42042fa544"
  }, {
    "url": "pwa-maskable-512x512.png",
    "revision": "53334bc832a48d6d2f4e9ccb0c00235f"
  }, {
    "url": "manifest.webmanifest",
    "revision": "f2b316622cce0d095a2e0e3e496408d2"
  }], {});
  workbox.cleanupOutdatedCaches();
  workbox.registerRoute(new workbox.NavigationRoute(workbox.createHandlerBoundToURL("index.html")));

}));
