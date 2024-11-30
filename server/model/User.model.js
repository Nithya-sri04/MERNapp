import mongoose from "mongoose";
import bcrypt from "bcrypt";

export const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, "Please provide a unique Username"],
        unique: true,
        trim: true,
    },
    password: {
        type: String,
        required: [true, "Please provide a password"],
    },
    email: {
        type: String,
        required: [true, "Please provide a unique email"],
        unique: true,
        trim: true,
    },
    firstName: { type: String, default: "" },
    lastName: { type: String, default: "" },
    mobile: { type: Number },
    address: { type: String, trim: true },
    profile: { type: String, default: "default-profile.png" },
});


UserSchema.pre("save", async function (next) {
    if (!this.isModified("password")) return next();
    this.password = await bcrypt.hash(this.password, 10);
    next();
});

export default mongoose.models.User || mongoose.model("User", UserSchema);
