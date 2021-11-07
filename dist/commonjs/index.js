"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Person = void 0;
// Export always from here for the types
var Person_1 = require("./person/Person");
Object.defineProperty(exports, "Person", { enumerable: true, get: function () { return Person_1.Person; } });
console.error("\nmy-module: Import error\n    You should import \"my-module/dist/commonJs/web\" or \"my-module/dist/commonJs/node\" (with lazy load or not) according the runtime environment.\n    There is also an \"es\" version instead of \"commonJs\", there imports are \"my-module/dist/esNext/web\" and \"my-module/dist/esNext/node\".\n    For typescript, you are free to import the types from \"my-module\" but functional code from \"web\" or \"node\" versions.\n");
//# sourceMappingURL=index.js.map