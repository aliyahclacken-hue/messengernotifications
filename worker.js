const PROJECT_ID = "messenger-e50bf";

const API_KEY = "AIzaSyA0seDdHj7OhNf6hx2-AZIDn1qhQpbFLTk";

const DATABASE_URL =

  "https://messenger-e50bf-default-rtdb.europe-west1.firebasedatabase.app";

const corsHeaders = {

  "Access-Control-Allow-Origin": "*",

  "Access-Control-Allow-Headers": "Authorization, Content-Type",

  "Access-Control-Allow-Methods": "POST, OPTIONS",

  "Content-Type": "application/json"

};

export default {

  async fetch(request, env) {

    if (request.method === "OPTIONS") {

      return new Response(null, {

        status: 204,

        headers: corsHeaders

      });

    }

    if (request.method !== "POST") {

      return json(

        { error: "Method not allowed." },

        405

      );

    }

    try {

      const firebaseIdToken =

        readBearerToken(request);

      const sender =

        await verifyFirebaseUser(

          firebaseIdToken

        );

      const url = new URL(request.url);

      const accessToken =

        await getGoogleAccessToken(env);

      if (url.pathname === "/repair-chats") {

        const result =

          await repairChatList(

            sender.localId,

            accessToken

          );

        return json(result);

      }

      const body =

        await request

          .json()

          .catch(() => ({}));

      const result =

        await sendChatNotifications(

          sender.localId,

          body,

          accessToken

        );

      return json(result);

    } catch (error) {

      console.error(error);

      return json(

        {

          error:

            error?.message ||

            "Unexpected Worker error."

        },

        error?.status || 500

      );

    }

  }

};

function json(value, status = 200) {

  return new Response(

    JSON.stringify(value),

    {

      status,

      headers: corsHeaders

    }

  );

}

function readBearerToken(request) {

  const header =

    request.headers.get(

      "Authorization"

    ) || "";

  if (!header.startsWith("Bearer ")) {

    const error =

      new Error(

        "You are not signed in."

      );

    error.status = 401;

    throw error;

  }

  return header.slice(7).trim();

}

async function verifyFirebaseUser(

  idToken

) {

  const response = await fetch(

    `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${API_KEY}`,

    {

      method: "POST",

      headers: {

        "Content-Type":

          "application/json"

      },

      body: JSON.stringify({

        idToken

      })

    }

  );

  const data =

    await response

      .json()

      .catch(() => ({}));

  if (

    !response.ok ||

    !data.users?.[0]?.localId

  ) {

    const firebaseMessage =

      data?.error?.message ||

      "INVALID_ID_TOKEN";

    const error =

      new Error(

        "The Worker could not verify your sign-in: " +

        firebaseMessage

      );

    error.status = 401;

    throw error;

  }

  return data.users[0];
 }

async function getGoogleAccessToken(

  env

) {

  const now =

    Math.floor(Date.now() / 1000);

  const header = base64Url(

    JSON.stringify({

      alg: "RS256",

      typ: "JWT"

    })

  );

  const claim = base64Url(

    JSON.stringify({

      iss:

        env.FIREBASE_CLIENT_EMAIL,

      scope:

        "https://www.googleapis.com/auth/firebase.database " +

        "https://www.googleapis.com/auth/firebase.messaging",

      aud:

        "https://oauth2.googleapis.com/token",

      iat: now,

      exp: now + 3600

    })

  );

  const unsigned =

    `${header}.${claim}`;

  const signature =

    await signRs256(

      unsigned,

      env.FIREBASE_PRIVATE_KEY

    );

  const assertion =

    `${unsigned}.${signature}`;

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

  const data =

    await response

      .json()

      .catch(() => ({}));

  if (

    !response.ok ||

    !data.access_token

  ) {

    throw new Error(

      data.error_description ||

      "Could not authenticate the Worker."

    );

  }

  return data.access_token;

}

async function signRs256(

  value,

  privateKeyText

) {

  let raw =

    String(privateKeyText || "")

      .trim();

  if (!raw) {

    throw new Error(

      "The Firebase private key is missing."

    );

  }

  try {

    const parsed = JSON.parse(raw);

    if (parsed?.private_key) {

      raw = parsed.private_key;

    }

  } catch {

    // The secret is already plain private-key text.

  }

  raw = raw

    .replace(/^["']|["']$/g, "")

    .replace(/\\\\n/g, "\n")

    .replace(/\\n/g, "\n")

    .trim();

  const match = raw.match(

    /-----BEGIN PRIVATE KEY-----([\s\S]*?)-----END PRIVATE KEY-----/

  );

  if (!match) {

    throw new Error(

      "The Firebase private key is not in the expected BEGIN PRIVATE KEY format."

    );

  }

  let pemBody =

    match[1].replace(/\s+/g, "");

  if (

    !/^[A-Za-z0-9+/]+={0,2}$/.test(

      pemBody

    )

  ) {

    throw new Error(

      "The Firebase private key contains unexpected characters."

    );

  }

  while (

    pemBody.length % 4 !== 0

  ) {

    pemBody += "=";

  }

  const binaryString =

    atob(pemBody);

  const binary =

    Uint8Array.from(

      binaryString,

      character =>

        character.charCodeAt(0)

    );

  const key =

    await crypto.subtle.importKey(

      "pkcs8",

      binary,

      {

        name:

          "RSASSA-PKCS1-v1_5",

        hash: "SHA-256"

      },

      false,

      ["sign"]

    );

  const signature =

    await crypto.subtle.sign(

      "RSASSA-PKCS1-v1_5",

      key,

      new TextEncoder().encode(

        value

      )

    );

  return bytesToBase64Url(

    new Uint8Array(signature)

  );

}

function base64Url(text) {

  return bytesToBase64Url(

    new TextEncoder().encode(text)

  );

}

function bytesToBase64Url(bytes) {

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

async function dbGet(

  path,

  accessToken

) {

  const response = await fetch(

    `${DATABASE_URL}/${path}.json?access_token=${encodeURIComponent(

      accessToken

    )}`

  );

  const data =

    await response

      .json()

      .catch(() => null);

  if (!response.ok) {

    throw new Error(

      `Database read failed for ${path}.`

    );

  }

  return data;

}

async function dbPatch(

  path,

  value,

  accessToken

) {

  const response = await fetch(

    `${DATABASE_URL}/${path}.json?access_token=${encodeURIComponent(

      accessToken

    )}`,

    {

      method: "PATCH",

      headers: {

        "Content-Type":

          "application/json"

      },

      body:

        JSON.stringify(value)

    }

  );

  if (!response.ok) {

    const text =

      await response

        .text()

        .catch(() => "");

    throw new Error(

      (

        "Database update failed. " +

        text

      ).trim()

    );

  }

}

async function repairChatList(

  uid,

  accessToken

) {

  const [

    allChats,

    allUsers,

    existingEntries

  ] = await Promise.all([

    dbGet(

      "chats",

      accessToken

    ),

    dbGet(

      "users",

      accessToken

    ),

    dbGet(

      `userChats/${uid}`,

      accessToken

    )

  ]);

  const chats =

    allChats || {};

  const users =

    allUsers || {};

  const current =

    existingEntries || {};

  const repaired = {};

  let found = 0;

  let created = 0;

  for (

    const [chatId, chat]

    of Object.entries(chats)

  ) {

    if (!chat?.members?.[uid]) {

      continue;

    }

    found += 1;

    const old =

      current[chatId] || {};

    const type =

      chat.type === "group"

        ? "group"

        : "individual";

    const updatedAt =

      chat.updatedAt ||

      chat.createdAt ||

      old.updatedAt ||

      0;

    const rawLastMessage =

      chat.lastMessage ||

      old.lastMessage ||

      "";

    const senderName =

      chat.lastMessageSenderName ||

      "";

    const lastMessage =

      senderName &&

      rawLastMessage &&

      !rawLastMessage.startsWith(

        `${senderName}:`

      )

        ? `${senderName}: ${rawLastMessage}`

        : rawLastMessage;

    let entry;

    if (type === "group") {

      entry = {

        ...old,

        type: "group",

        chatName:

          chat.name ||

          old.chatName ||

          "Group",

        updatedAt,

        lastMessage,

        unreadCount: Number(

          old.unreadCount || 0
         )

      };

    } else {

      const memberIds =

        Object.keys(

          chat.members || {}

        );

      const otherUid =

        memberIds.find(

          memberUid =>

            memberUid !== uid

        ) ||

        old.otherUid ||

        "";

      const otherName =

        users?.[otherUid]

          ?.displayName ||

        old.otherName ||

        old.chatName ||

        "Conversation";

      entry = {

        ...old,

        type: "individual",

        otherUid,

        otherName,

        chatName:

          old.nickname ||

          otherName,

        updatedAt,

        lastMessage,

        unreadCount: Number(

          old.unreadCount || 0

        )

      };

    }

    repaired[chatId] = entry;

    if (!current[chatId]) {

      created += 1;

    }

  }

  if (

    Object.keys(repaired).length

  ) {

    await dbPatch(

      `userChats/${uid}`,

      repaired,

      accessToken

    );

  }

  return {

    ok: true,

    chatsFound: found,

    entriesCreated: created,

    message:

      found === 1

        ? "1 chat loaded."

        : `${found} chats loaded.`

  };

}

async function sendChatNotifications(

  senderUid,

  body,

  accessToken

) {

  const chatId =

    String(

      body.chatId || ""

    ).trim();

  const senderName =

    String(

      body.senderName ||

      "New message"

    ).slice(0, 80);

  const messageText =

    String(

      body.messageText || ""

    ).slice(0, 500);

  if (!chatId || !messageText) {

    const error =

      new Error(

        "The notification request is incomplete."

      );

    error.status = 400;

    throw error;

  }

  const chat =

    await dbGet(

      `chats/${chatId}`,

      accessToken

    );

  if (

    !chat?.members?.[senderUid]

  ) {

    const error =

      new Error(

        "You are not a member of this chat."

      );

    error.status = 403;

    throw error;

  }

  const members =

    Object.keys(

      chat.members || {}

    ).filter(

      uid =>

        uid !== senderUid

    );

  let sent = 0;

  let skipped = 0;

  for (

    const recipientUid

    of members

  ) {

    const [

      recipientBlocksSender,

      senderBlocksRecipient,

      chatEntry,

      tokenMap

    ] = await Promise.all([

      dbGet(

        `blocks/${recipientUid}/${senderUid}`,

        accessToken

      ),

      dbGet(

        `blocks/${senderUid}/${recipientUid}`,

        accessToken

      ),

      dbGet(

        `userChats/${recipientUid}/${chatId}`,

        accessToken

      ),

      dbGet(

        `notificationTokens/${recipientUid}`,

        accessToken

      )

    ]);

    const muteUntil =

      chatEntry?.muteUntil;

    const muted =

      muteUntil === "always" ||

      Number(muteUntil || 0) >

        Date.now();

    if (

      recipientBlocksSender ||

      senderBlocksRecipient ||

      muted

    ) {

      skipped += 1;

      continue;

    }

    const tokens =

      Object.values(

        tokenMap || {}

      )

        .map(

          value =>

            value?.token

        )

        .filter(Boolean);

    if (!tokens.length) {

      skipped += 1;

      continue;

    }

    const title =

      chat.type === "group"

        ? `${senderName} in ${

            chat.name || "Group"

          }`

        : senderName;

    for (const token of tokens) {

      const response =

        await fetch(

          `https://fcm.googleapis.com/v1/projects/${PROJECT_ID}/messages:send`,

          {

            method: "POST",

            headers: {

              Authorization:

                `Bearer ${accessToken}`,

              "Content-Type":

                "application/json"

            },

            body:

              JSON.stringify({

                message: {

                  token,

                  notification: {

                    title,

                    body:

                      messageText

                  },

                  data: {

                    chatId,

                    senderUid,

                    senderName,

                    messageText,

                    chatType:

                      chat.type ||

                      "individual",

                    chatName:

                      chat.name || ""

                  },

                  webpush: {

                    fcm_options: {

                      link:

                        "https://aliyahclacken-hue.github.io/messenger-/" +

                        `?chatId=${encodeURIComponent(

                          chatId

                        )}` +

                        `&senderUid=${encodeURIComponent(

                          senderUid

                        )}` +

                        `&senderName=${encodeURIComponent(

                          senderName

                        )}` +

                        `&messageText=${encodeURIComponent(

                          messageText

                        )}` +

                        `&chatType=${encodeURIComponent(

                          chat.type ||

                          "individual"

                        )}`

                    }

                  }

                }

              })

          }

        );

      if (response.ok) {

        sent += 1;

      } else {

        console.error(

          "FCM send failed",

          await response

            .text()

            .catch(() => "")

        );

      }

    }

  }

  return {

    ok: true,

    sent,

    skipped,

    message:

      sent

        ? "Notification sent."

        : "No notification-enabled recipients were available."

  };

}
