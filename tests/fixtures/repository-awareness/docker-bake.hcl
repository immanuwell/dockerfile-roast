variable "BAKE_CONTEXT" {
  default = "contexts/bake"
}

target "bake-base" {
  context = BAKE_CONTEXT
  dockerfile = "../../docker/bake.build"
}

target "bake" {
  inherits = ["bake-base"]
}
