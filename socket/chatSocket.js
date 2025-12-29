export const chatSocket = (io) => {
  io.on("connection", (socket) => {
    console.log("A user connected:", socket.id);

    // Join a room (user-specific)
    socket.on("joinRoom", (roomId) => {
      socket.join(roomId);
    });

    // Send a message
    socket.on("chatMessage", async ({ senderId, receiverId, message, db }) => {
      try {
        await db.query(
          "INSERT INTO messages (sender_id, receiver_id, message) VALUES ($1, $2, $3)",
          [senderId, receiverId, message]
        );

        const roomId = [senderId, receiverId].sort().join("_"); // same room for both users
        io.to(roomId).emit("messageReceived", { senderId, message, createdAt: new Date() });
      } catch (err) {
        console.log("Socket chat error:", err);
      }
    });

    socket.on("disconnect", () => {
      console.log("User disconnected:", socket.id);
    });
  });
};
