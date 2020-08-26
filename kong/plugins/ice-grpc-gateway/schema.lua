return {
  name = "ice-grpc-gateway",
  fields = {
    { config = {
      type = "record",
      fields = {
        {
          proto = {
            type = "string",
            required = true,
            default = nil,
          },
        },
        {
          md5 = {
            type = "string",
            required = true,
            default = nil,
          },
        },
      },
    }, },
  },
}
