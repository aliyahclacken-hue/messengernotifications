const PROJECT_ID = "messenger-e50bf";

const FIREBASE_API_KEY =

  "AIzaSyA0seDdHj7OhNf6hx2-AZIDn1qhQpbFLTk";

const DATABASE_URL =

  "https://messenger-e50bf-default-rtdb.europe-west1.firebasedatabase.app";

const ALLOWED_ORIGIN =

  "https://aliyahclacken-hue.github.io";

export default {

  async fetch(request, env) {

    const corsHeaders = {

      "Access-Control-Allow-Origin": ALLOWED_ORIGIN,

      "Access-Control-Allow-Headers":

        "Authorization, Content-Type",

      "Access-Control-Allow-Methods": "POST, OPTIONS",

      "Content-Type": "application/json"

    };

    if (request.method === "OPTIONS") {

      return new Response(null, {

        status: 204,

        headers: corsHeaders

      });

    }

    if (request.method !== "POST") {

      return jsonResponse(

        {

          error: "Use a POST request."

        },

        405,

        corsHeaders

      );

    }

    try {

      const origin = request.headers.get("Origin");

      if (origin && origin !== ALLOWED_ORIGIN) {

        return jsonResponse(

          {

            error: "This website is not allowed."

          },

          403,

          corsHeaders

        );

      }

      const authorization =

        request.headers.get("Authorization") || "";

      if (!authorization.startsWith("Bearer ")) {

        return jsonResponse(

          {

            error: "You must be signed in."

          },

          401,

          corsHeaders

        );

      }

      const firebaseIdToken =

        authorization.slice(7);

      const sender =

        await verifyFirebaseUser(firebaseIdToken);

      if (!sender?.localId) {

        return jsonResponse(

          {

            error: "The sign-in could not be verified."

          },

          401,

          corsHeaders

        );

      }

      const body = await request.json();

      const recipientUid =

        typeof body.recipientUid === "string"

          ? body.recipientUid.trim()

          : "";

      const chatId =

        typeof body.chatId === "string"

          ? body.chatId.trim()

          : "";

      const senderName =

        typeof body.senderName === "string"

          ? body.senderName.trim().slice(0, 40)

          : "New message";

      const messageText =

        typeof body.messageText === "string"

          ? body.messageText.trim().slice(0, 200)

          : "";

      if (!recipientUid || !chatId || !messageText) {

        return jsonResponse(

          {

            error:

              "Notification information is missing."

          },

          400,

          corsHeaders

        );

      }

      if (recipientUid === sender.localId) {

        return jsonResponse(

          {

            error:

              "You cannot notify your own account."

          },

          400,

          corsHeaders

        );

      }

      const accessToken =

        await getGoogleAccessToken(env);

      const members =

        await readFirebasePath(

          `chats/${encodeURIComponent(chatId)}/members`,

          accessToken

        );

      if (

        members?.[sender.localId] !== true ||

        members?.[recipientUid] !== true

      ) {

        return jsonResponse(

          {

            error:

              "You are not both members of this chat."

          },

          403,

          corsHeaders

        );

      }

      const tokenRecords =

        await readFirebasePath(

          `notificationTokens/${encodeURIComponent(

            recipientUid

          )}`,

          accessToken

        );

      if (

        !tokenRecords ||

        typeof tokenRecords !== "object"

      ) {

        return jsonResponse(

          {

            success: true,

            sent: 0,

            message:

              "The other person has not enabled notifications."

          },

          200,

          corsHeaders

        );

      }

      const deviceTokens =

        Object.values(tokenRecords)

          .map(record => record?.token)

          .filter(

            token =>

              typeof token === "string" &&

              token.length > 0

          );

      if (deviceTokens.length === 0) {

        return jsonResponse(

          {

            success: true,

            sent: 0,

            message:

              "The other person has not enabled notifications."

          },

          200,

          corsHeaders

        );

      }

      let sent = 0;

      const errors = [];

      for (const deviceToken of deviceTokens) {

        const result =

          await sendFirebaseNotification(

            accessToken,

            deviceToken,

            senderName,

            messageText,

            chatId,

            sender.localId

          );

        if (result.ok) {

          sent += 1;

        } else {

          errors.push(result.error);

        }

      }

      return jsonResponse(

        {

          success: sent > 0,

          sent,

          failed: errors.length,

          errors

        },

        sent > 0 ? 200 : 502,

        corsHeaders

      );

    } catch (error) {

      console.error(

        "Notification error:",

        error

      );

      return jsonResponse(

        {

          error:

            error instanceof Error

              ? error.message

              : "The notification could not be sent."

        },

        500,

        corsHeaders

      );

    }

  }

};

async function verifyFirebaseUser(idToken) {

  const response = await fetch(

    `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${FIREBASE_API_KEY}`,

    {

      method: "POST",

      headers: {

        "Content-Type": "application/json"

      },

      body: JSON.stringify({

        idToken

      })

    }

  );

  if (!response.ok) {

    return null;

  }

  const data = await response.json();

  return data.users?.[0] || null;

}

async function readFirebasePath(

  path,

  accessToken

) {

  const response = await fetch(

    `${DATABASE_URL}/${path}.json`,

    {

      headers: {

        Authorization: `Bearer ${accessToken}`

      }

    }

  );

  if (!response.ok) {

    const text = await response.text();

    throw new Error(

      `Firebase database error: ${response.status} ${text}`

    );

  }

  return response.json();

}

async function sendFirebaseNotification(

  accessToken,

  deviceToken,

  senderName,

  messageText,

  chatId,

  senderUid

) {

  const response = await fetch(

    `https://fcm.googleapis.com/v1/projects/${PROJECT_ID}/messages:send`,

    {

      method: "POST",

      headers: {

        Authorization: `Bearer ${accessToken}`,

        "Content-Type": "application/json"

      },

      body: JSON.stringify({

        message: {

          token: deviceToken,

          notification: {

            title: senderName,

            body: messageText

          },

          data: {

            chatId,

            senderUid

          },

          webpush: {

            notification: {

              tag: chatId,

              renotify: true

            },

            fcm_options: {

              link:

                "https://aliyahclacken-hue.github.io/messenger-/"

            }

          }

        }

      })

    }

  );

  if (response.ok) {

    return {

      ok: true

    };

  }

  const errorText =

    await response.text();

  return {

    ok: false,

    error:

      `${response.status}: ${errorText}`

  };

}

async function getGoogleAccessToken(env) {

  if (

    !env.FIREBASE_CLIENT_EMAIL ||

    !env.FIREBASE_PRIVATE_KEY

  ) {

    throw new Error(

      "The Firebase secrets have not been added to Cloudflare yet."

    );

  }

  const now =

    Math.floor(Date.now() / 1000);

  const header = {

    alg: "RS256",

    typ: "JWT"

  };

  const payload = {

    iss: env.FIREBASE_CLIENT_EMAIL,

    sub: env.FIREBASE_CLIENT_EMAIL,
     aud:

      "https://oauth2.googleapis.com/token",

    scope: [

      "https://www.googleapis.com/auth/firebase.messaging",

      "https://www.googleapis.com/auth/firebase.database",

      "https://www.googleapis.com/auth/userinfo.email"

    ].join(" "),

    iat: now,

    exp: now + 3600

  };

  const unsignedToken =

    `${base64UrlJson(header)}.${base64UrlJson(

      payload

    )}`;

  const privateKey =

    await importPrivateKey(

      env.FIREBASE_PRIVATE_KEY

    );

  const signature =

    await crypto.subtle.sign(

      {

        name: "RSASSA-PKCS1-v1_5"

      },

      privateKey,

      new TextEncoder().encode(

        unsignedToken

      )

    );

  const assertion =

    `${unsignedToken}.${base64UrlBytes(

      new Uint8Array(signature)

    )}`;

  const response = await fetch(

    "https://oauth2.googleapis.com/token",

    {

      method: "POST",

      headers: {

        "Content-Type":

          "application/x-www-form-urlencoded"

      },

      body: new URLSearchParams({

        grant_type:

          "urn:ietf:params:oauth:grant-type:jwt-bearer",

        assertion

      })

    }

  );

  const data = await response.json();

  if (

    !response.ok ||

    !data.access_token

  ) {

    throw new Error(

      `Google sign-in error: ${JSON.stringify(

        data

      )}`

    );

  }

  return data.access_token;

}

async function importPrivateKey(pem) {

  let cleanedPem =

    String(pem).trim();

  if (cleanedPem.startsWith('"')) {

    try {

      cleanedPem = JSON.parse(

        cleanedPem.endsWith(",")

          ? cleanedPem.slice(0, -1)

          : cleanedPem

      );

    } catch {

      cleanedPem = cleanedPem

        .replace(/^"/, "")

        .replace(/",?$/, "");

    }

  }

  cleanedPem = cleanedPem

    .replace(/\\n/g, "\n")

    .replace(

      /-----BEGIN PRIVATE KEY-----/g,

      ""

    )

    .replace(

      /-----END PRIVATE KEY-----/g,

      ""

    )

    .replace(

      /[^A-Za-z0-9+/=]/g,

      ""

    );

  while (

    cleanedPem.length % 4 !== 0

  ) {

    cleanedPem += "=";

  }

  const binary =

    Uint8Array.from(

      atob(cleanedPem),

      character =>

        character.charCodeAt(0)

    );

  return crypto.subtle.importKey(

    "pkcs8",

    binary.buffer,

    {

      name: "RSASSA-PKCS1-v1_5",

      hash: "SHA-256"

    },

    false,

    ["sign"]

  );

}

function base64UrlJson(value) {

  return base64UrlBytes(

    new TextEncoder().encode(

      JSON.stringify(value)

    )

  );

}

function base64UrlBytes(bytes) {

  let binary = "";

  for (const byte of bytes) {

    binary +=

      String.fromCharCode(byte);

  }

  return btoa(binary)

    .replace(/\+/g, "-")

    .replace(/\//g, "_")

    .replace(/=+$/g, "");

}

function jsonResponse(

  value,

  status,

  headers

) {

  return new Response(

    JSON.stringify(value),

    {

      status,

      headers

    }

  );

}
