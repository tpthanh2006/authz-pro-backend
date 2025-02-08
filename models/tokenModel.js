const mongoose = require("mongoose");

const tokenSchema = mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: "user"
    },
    vToken: {
      type: String,
      default: "",
    },
    rToken: {
      type: String,
      default: "",
    },
    lToken: {
      type: String,
      default: "",
    },
    createdAt: {
      type: Date,
      required: true
    },
    expiredAt: {
      type: Date,
      required: true
    },
  },
  {
    timestamps: true,
    minimize: false
  }
)

const Token = mongoose.model("Token", tokenSchema);
module.exports = Token;