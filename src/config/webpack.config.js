module.exports = {
    resolve: {
      fallback: {
        "http": require.resolve("stream-http"),  // 'http' 모듈에 대한 폴리필 추가
        "https": require.resolve("https-browserify"),  // 'https' 모듈에 대한 폴리필 추가
        "stream": require.resolve("stream-browserify"),  // 'stream' 모듈에 대한 폴리필 추가
        "path": require.resolve("path-browserify"),  // 'path' 모듈에 대한 폴리필 추가
        "crypto": require.resolve("crypto-browserify"),  // 'crypto' 모듈에 대한 폴리필 추가
        "zlib": require.resolve("browserify-zlib"),  // 'zlib' 모듈에 대한 폴리필 추가
        "querystring": require.resolve("querystring-es3"),  // 'querystring' 모듈에 대한 폴리필 추가
        "util": require.resolve("util/"),  // 'util' 모듈에 대한 폴리필 추가
        "fs": false,  // 'fs'는 브라우저에서 사용할 수 없으므로 빈 모듈로 처리
        "net": false  // 'net'도 브라우저에서 사용할 수 없으므로 빈 모듈로 처리
      }
    }
  };
  