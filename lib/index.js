const { promisify } = require("util");
const jwt = require("jsonwebtoken");
const UnauthorizedError = require("./errors/UnauthorizedError");

const wrapAsync = f => (req, res, next) => f(req).catch(next);

module.exports = options => {
  if (!options || !options.secret) throw new Error("secret should be set");

  const secretCallback = options.secret;

  const isRevokedCallback = options.isRevoked || (() => false);

  const requestProperty =
    options.userProperty || options.requestProperty || "user";
  const credentialsRequired = !!options.credentialsRequired;

  return wrapAsync(async req => {
    if (
      req.method === "OPTIONS" &&
      Object.prototype.hasOwnProperty.call(
        req.headers,
        "access-control-request-headers"
      )
    ) {
      const hasAuthInAccessControl = req.headers[
        "access-control-request-headers"
      ]
        .split(",")
        .map(header => header.trim())
        .includes("authorization");

      if (hasAuthInAccessControl) {
        return;
      }
    }

    let token;
    if (options.getToken && typeof options.getToken === "function") {
      token = options.getToken(req);
    } else if (req.headers && req.headers.authorization) {
      const parts = req.headers.authorization.split(" ");
      if (parts.length === 2) {
        const [scheme, credentials] = parts;

        if (/^Bearer$/i.test(scheme)) {
          token = credentials;
        } else {
          throw new UnauthorizedError("credentials_bad_scheme", {
            message: "Format is Authorization: Bearer [token]"
          });
        }
      } else {
        throw new UnauthorizedError("credentials_bad_format", {
          message: "Format is Authorization: Bearer [token]"
        });
      }
    }

    if (!token) {
      if (credentialsRequired) {
        throw new UnauthorizedError("credentials_required", {
          message: "No authorization token was found"
        });
      } else {
        return;
      }
    }

    let dtoken;

    try {
      dtoken = jwt.decode(token, { complete: true }) || {};
    } catch (err) {
      throw new UnauthorizedError("invalid_token", err);
    }

    const secret = await secretCallback(req, dtoken.header, dtoken.payload);

    let decoded;
    try {
      decoded = promisify(jwt.verify)(token, secret, options);
    } catch (err) {
      throw new UnauthorizedError("invalid_token", err);
    }

    const revoked = await isRevokedCallback(req, dtoken.payload);
    if (revoked) {
      throw new UnauthorizedError("revoked_token", {
        message: "The token has been revoked."
      });
    }

    req[requestProperty] = decoded;
  });
};

module.exports.UnauthorizedError = UnauthorizedError;
