require("dotenv").config();   // ⭐ 이 줄이 핵심

const app = require("./app");
const PORT = process.env.PORT || 3000;

app.listen(PORT, () =>
  console.log(`SNF SEMI local → http://localhost:${PORT}`)
);
