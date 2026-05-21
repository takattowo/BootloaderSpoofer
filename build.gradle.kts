tasks.register("clean", Delete::class) {
    delete(rootProject.layout.buildDirectory)
}
