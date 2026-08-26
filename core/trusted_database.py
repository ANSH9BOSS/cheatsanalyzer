"""
ANSH9BOSS Trusted Official Mods Database
Pre-computed signatures and metadata for popular legit Minecraft mods
to eliminate false positives.
"""

# Official Whitelist Mod IDs and Names
OFFICIAL_MODS_WHITELIST = {
    # Performance & Optimization
    "sodium", "sodium-extra", "reeses-sodium-options", "iris", "lithium", "ferrite-core",
    "indium", "immediatelyfast", "entityculling", "krypton", "dynamic-fps", "memoryleakfix",
    "c2me", "starlight", "vulkanmod", "modernfix", "embeddium", "oculus", "optifine",
    
    # Core Libraries & APIs
    "fabric-api", "fabric-language-kotlin", "forge", "neoforge", "quilt_loader",
    "cloth-config", "cloth-config2", "yetanotherconfiglib", "architectury", "cloth_api",
    "modmenu", "balm", "curios", "geckolib", "patchouli", "citresewn",
    
    # HUD, UI & Quality of Life
    "jei", "rei", "emi", "appleskin", "journeymap", "xaeros_minimap", "xaeros_world_map",
    "voxelmap", "inventoryprofilesnext", "invmove", "itemscroller", "mousewheelie",
    "zoomify", "logical_zoom", "wi_zoom", "shulkerboxtooltip", "controlling", "searchables",
    
    # Technical & Schematics
    "litematica", "malilib", "minihud", "tweakeroo", "itemphysic", "presencefootsteps",
    "soundphysics", "simplevoicechat", "plasmovoice", "audioplayer", "chat_heads",
    "customskinloader", "skinport", "3dskinlayers", "waveycapes", "notenoughanimations",
    
    # Popular Legit PvP Clients
    "lunarclient", "feather", "badlion", "labymod", "essential"
}

# Known Safe Manifest Identifiers
SAFE_MANIFEST_IDENTIFIERS = [
    "net.caffeinemc.sodium",
    "net.coderbot.iris",
    "me.jellysquid.mods.lithium",
    "me.jellysquid.mods.sodium",
    "net.fabricmc.fabric",
    "org.quiltmc",
    "net.minecraftforge",
    "dev.architectury",
    "me.shedaniel.cloth",
    "com.mrcrayfish",
    "fi.dy.mario.malilib"
]
