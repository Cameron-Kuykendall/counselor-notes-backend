// server.js (root entry point for Elastic Beanstalk or local run)
const app = require("./counselor-app/app.js");
const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});

