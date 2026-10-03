/* a Vulkan fixture that draws rather than enumerates: it picks the physical device whose
 * name carries the filter it was given, runs a compute shader that fills a buffer with a
 * known pattern, and reads the buffer back to prove the ICD produced the values. the name
 * and the driver it prints are the loader's answer, so one run covers both. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vulkan/vulkan.h>

#define ELEMENTS 4096
#define GROUP 64

static int fail(const char *what, const char *detail)
{
    fprintf(stderr, "vulkan-draw: %s: %s\n", what, detail);
    return 1;
}

static uint32_t pattern(uint32_t index)
{
    return index * 7u + 3u;
}

int main(int argc, char **argv)
{
    const char *module_path;
    const char *filter;
    VkInstanceCreateInfo instance_info;
    VkInstance instance = VK_NULL_HANDLE;
    VkPhysicalDevice physical = VK_NULL_HANDLE;
    VkDevice device = VK_NULL_HANDLE;
    VkQueue queue = VK_NULL_HANDLE;
    uint32_t count = 0, i, queue_family = 0;
    int have_family = 0;
    FILE *stream;
    long module_size;
    void *code = NULL;
    VkShaderModule shader = VK_NULL_HANDLE;
    VkDescriptorSetLayout set_layout = VK_NULL_HANDLE;
    VkPipelineLayout pipeline_layout = VK_NULL_HANDLE;
    VkPipeline pipeline = VK_NULL_HANDLE;
    VkDescriptorPool pool = VK_NULL_HANDLE;
    VkDescriptorSet set = VK_NULL_HANDLE;
    VkCommandPool command_pool = VK_NULL_HANDLE;
    VkCommandBuffer command_buffer = VK_NULL_HANDLE;
    VkDeviceMemory memory = VK_NULL_HANDLE;
    VkBuffer buffer = VK_NULL_HANDLE;
    VkDeviceSize allocated = 0;
    void *mapped = NULL;
    uint32_t *values = NULL;
    uint32_t mismatches = 0;
    char name[VK_MAX_PHYSICAL_DEVICE_NAME_SIZE];
    char driver[256];
    int status = 1;

    if (argc != 3)
        return fail("usage: vulkan-draw MODULE.spv DEVICE-FILTER", "two arguments required");
    module_path = argv[1];
    filter = argv[2];

    memset(&instance_info, 0, sizeof instance_info);
    instance_info.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    /* the driver-properties query the fixture prints is core from 1.2, so an instance left at
     * the 1.0 default would hand back an empty driver name for a device that has one */
    uint32_t loader_version = VK_API_VERSION_1_0;
    if (vkEnumerateInstanceVersion(&loader_version) != VK_SUCCESS)
        loader_version = VK_API_VERSION_1_0;
    VkApplicationInfo application;
    memset(&application, 0, sizeof application);
    application.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    application.pApplicationName = "holy-matrix-vulkan-draw";
    application.apiVersion = loader_version < VK_API_VERSION_1_3 ? loader_version
                                                                : VK_API_VERSION_1_3;
    instance_info.pApplicationInfo = &application;
    if (vkCreateInstance(&instance_info, NULL, &instance) != VK_SUCCESS)
        return fail("vkCreateInstance", "the loader refused an instance with no extensions");

    if (vkEnumeratePhysicalDevices(instance, &count, NULL) != VK_SUCCESS || count == 0) {
        vkDestroyInstance(instance, NULL);
        return fail("vkEnumeratePhysicalDevices", "no ICD offered a device");
    }
    VkPhysicalDevice *devices = calloc(count, sizeof *devices);
    if (!devices) {
        vkDestroyInstance(instance, NULL);
        return fail("calloc", "out of memory");
    }
    if (vkEnumeratePhysicalDevices(instance, &count, devices) != VK_SUCCESS) {
        free(devices);
        vkDestroyInstance(instance, NULL);
        return fail("vkEnumeratePhysicalDevices", "the second count did not match");
    }
    for (i = 0; i < count; i++) {
        VkPhysicalDeviceProperties properties;
        vkGetPhysicalDeviceProperties(devices[i], &properties);
        if (strstr(properties.deviceName, filter)) {
            physical = devices[i];
            break;
        }
    }
    if (!physical) {
        fprintf(stderr, "vulkan-draw: devices:");
        for (i = 0; i < count; i++) {
            VkPhysicalDeviceProperties properties;
            vkGetPhysicalDeviceProperties(devices[i], &properties);
            fprintf(stderr, " %s", properties.deviceName);
        }
        fprintf(stderr, "\n");
        free(devices);
        vkDestroyInstance(instance, NULL);
        return fail("device filter", "no device carries the requested name");
    }

    VkPhysicalDeviceDriverProperties driver_properties;
    memset(&driver_properties, 0, sizeof driver_properties);
    driver_properties.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DRIVER_PROPERTIES;
    VkPhysicalDeviceProperties2 properties2;
    memset(&properties2, 0, sizeof properties2);
    properties2.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2;
    properties2.pNext = &driver_properties;
    vkGetPhysicalDeviceProperties2(physical, &properties2);
    strncpy(name, properties2.properties.deviceName, sizeof name - 1);
    strncpy(driver, driver_properties.driverName, sizeof driver - 1);

    vkGetPhysicalDeviceQueueFamilyProperties(physical, &count, NULL);
    VkQueueFamilyProperties *families = calloc(count ? count : 1, sizeof *families);
    if (!families) {
        free(devices);
        vkDestroyInstance(instance, NULL);
        return fail("calloc", "out of memory");
    }
    vkGetPhysicalDeviceQueueFamilyProperties(physical, &count, families);
    for (i = 0; i < count; i++) {
        if (families[i].queueFlags & VK_QUEUE_COMPUTE_BIT) {
            queue_family = i;
            have_family = 1;
            break;
        }
    }
    free(families);
    free(devices);
    if (!have_family) {
        vkDestroyInstance(instance, NULL);
        return fail("queue families", "no family offers compute");
    }

    stream = fopen(module_path, "rb");
    if (!stream) {
        vkDestroyInstance(instance, NULL);
        return fail("fopen", module_path);
    }
    fseek(stream, 0, SEEK_END);
    module_size = ftell(stream);
    fseek(stream, 0, SEEK_SET);
    if (module_size <= 0 || module_size % 4 != 0) {
        fclose(stream);
        vkDestroyInstance(instance, NULL);
        return fail("fread", "the module is not a SPIR-V word count");
    }
    code = malloc((size_t)module_size);
    if (!code || fread(code, 1, (size_t)module_size, stream) != (size_t)module_size) {
        fclose(stream);
        free(code);
        vkDestroyInstance(instance, NULL);
        return fail("fread", "the module did not read");
    }
    fclose(stream);

    const float priority = 1.0f;
    VkDeviceQueueCreateInfo queue_info;
    memset(&queue_info, 0, sizeof queue_info);
    queue_info.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queue_info.queueFamilyIndex = queue_family;
    queue_info.queueCount = 1;
    queue_info.pQueuePriorities = &priority;
    VkDeviceCreateInfo device_info;
    memset(&device_info, 0, sizeof device_info);
    device_info.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    device_info.queueCreateInfoCount = 1;
    device_info.pQueueCreateInfos = &queue_info;
    if (vkCreateDevice(physical, &device_info, NULL, &device) != VK_SUCCESS) {
        free(code);
        vkDestroyInstance(instance, NULL);
        return fail("vkCreateDevice", "the ICD refused a compute device");
    }
    vkGetDeviceQueue(device, queue_family, 0, &queue);

    VkShaderModuleCreateInfo module_info;
    memset(&module_info, 0, sizeof module_info);
    module_info.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    module_info.codeSize = (size_t)module_size;
    module_info.pCode = code;
    if (vkCreateShaderModule(device, &module_info, NULL, &shader) != VK_SUCCESS)
        goto done;

    VkDescriptorSetLayoutBinding binding;
    memset(&binding, 0, sizeof binding);
    binding.binding = 0;
    binding.descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    binding.descriptorCount = 1;
    binding.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    VkDescriptorSetLayoutCreateInfo set_info;
    memset(&set_info, 0, sizeof set_info);
    set_info.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    set_info.bindingCount = 1;
    set_info.pBindings = &binding;
    if (vkCreateDescriptorSetLayout(device, &set_info, NULL, &set_layout) != VK_SUCCESS)
        goto done;

    VkPipelineLayoutCreateInfo layout_info;
    memset(&layout_info, 0, sizeof layout_info);
    layout_info.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    layout_info.setLayoutCount = 1;
    layout_info.pSetLayouts = &set_layout;
    if (vkCreatePipelineLayout(device, &layout_info, NULL, &pipeline_layout) != VK_SUCCESS)
        goto done;

    VkComputePipelineCreateInfo pipeline_info;
    memset(&pipeline_info, 0, sizeof pipeline_info);
    pipeline_info.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    pipeline_info.stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    pipeline_info.stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    pipeline_info.stage.module = shader;
    pipeline_info.stage.pName = "main";
    pipeline_info.layout = pipeline_layout;
    if (vkCreateComputePipelines(device, VK_NULL_HANDLE, 1, &pipeline_info, NULL, &pipeline)
        != VK_SUCCESS)
        goto done;

    VkDescriptorPoolSize size;
    memset(&size, 0, sizeof size);
    size.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    size.descriptorCount = 1;
    VkDescriptorPoolCreateInfo pool_info;
    memset(&pool_info, 0, sizeof pool_info);
    pool_info.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    pool_info.maxSets = 1;
    pool_info.poolSizeCount = 1;
    pool_info.pPoolSizes = &size;
    if (vkCreateDescriptorPool(device, &pool_info, NULL, &pool) != VK_SUCCESS)
        goto done;
    VkDescriptorSetAllocateInfo allocate;
    memset(&allocate, 0, sizeof allocate);
    allocate.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    allocate.descriptorPool = pool;
    allocate.descriptorSetCount = 1;
    allocate.pSetLayouts = &set_layout;
    if (vkAllocateDescriptorSets(device, &allocate, &set) != VK_SUCCESS)
        goto done;

    VkBufferCreateInfo buffer_info;
    memset(&buffer_info, 0, sizeof buffer_info);
    buffer_info.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    buffer_info.size = ELEMENTS * sizeof(uint32_t);
    buffer_info.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;
    buffer_info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    if (vkCreateBuffer(device, &buffer_info, NULL, &buffer) != VK_SUCCESS)
        goto done;
    VkMemoryRequirements requirements;
    vkGetBufferMemoryRequirements(device, buffer, &requirements);
    allocated = requirements.size;
    VkPhysicalDeviceMemoryProperties memory_properties;
    vkGetPhysicalDeviceMemoryProperties(physical, &memory_properties);
    uint32_t type_bits = 0;
    for (i = 0; i < memory_properties.memoryTypeCount; i++) {
        if (!(requirements.memoryTypeBits & (1u << i)))
            continue;
        if (!(memory_properties.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT))
            continue;
        if (!(memory_properties.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_HOST_COHERENT_BIT))
            continue;
        type_bits = i;
        break;
    }
    if (type_bits == 0 && memory_properties.memoryTypeCount > 0)
        type_bits = 0;
    VkMemoryAllocateInfo allocate_info;
    memset(&allocate_info, 0, sizeof allocate_info);
    allocate_info.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    allocate_info.allocationSize = allocated;
    allocate_info.memoryTypeIndex = type_bits;
    if (vkAllocateMemory(device, &allocate_info, NULL, &memory) != VK_SUCCESS)
        goto done;
    if (vkBindBufferMemory(device, buffer, memory, 0) != VK_SUCCESS)
        goto done;

    VkDescriptorBufferInfo descriptor_buffer;
    memset(&descriptor_buffer, 0, sizeof descriptor_buffer);
    descriptor_buffer.buffer = buffer;
    descriptor_buffer.offset = 0;
    descriptor_buffer.range = VK_WHOLE_SIZE;
    VkWriteDescriptorSet write;
    memset(&write, 0, sizeof write);
    write.sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
    write.dstSet = set;
    write.dstBinding = 0;
    write.descriptorCount = 1;
    write.descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    write.pBufferInfo = &descriptor_buffer;
    vkUpdateDescriptorSets(device, 1, &write, 0, NULL);

    VkCommandPoolCreateInfo command_pool_info;
    memset(&command_pool_info, 0, sizeof command_pool_info);
    command_pool_info.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    command_pool_info.queueFamilyIndex = queue_family;
    command_pool_info.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    if (vkCreateCommandPool(device, &command_pool_info, NULL, &command_pool) != VK_SUCCESS)
        goto done;
    VkCommandBufferAllocateInfo command_allocate;
    memset(&command_allocate, 0, sizeof command_allocate);
    command_allocate.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    command_allocate.commandPool = command_pool;
    command_allocate.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    command_allocate.commandBufferCount = 1;
    if (vkAllocateCommandBuffers(device, &command_allocate, &command_buffer) != VK_SUCCESS)
        goto done;
    VkCommandBufferBeginInfo begin;
    memset(&begin, 0, sizeof begin);
    begin.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    if (vkBeginCommandBuffer(command_buffer, &begin) != VK_SUCCESS)
        goto done;
    vkCmdBindPipeline(command_buffer, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline);
    vkCmdBindDescriptorSets(command_buffer, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline_layout,
                            0, 1, &set, 0, NULL);
    vkCmdDispatch(command_buffer, ELEMENTS / GROUP, 1, 1);
    VkMemoryBarrier barrier;
    memset(&barrier, 0, sizeof barrier);
    barrier.sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER;
    barrier.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
    barrier.dstAccessMask = VK_ACCESS_HOST_READ_BIT;
    vkCmdPipelineBarrier(command_buffer, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                         VK_PIPELINE_STAGE_HOST_BIT, 0, 1, &barrier, 0, NULL, 0, NULL);
    if (vkEndCommandBuffer(command_buffer) != VK_SUCCESS)
        goto done;
    VkSubmitInfo submit;
    memset(&submit, 0, sizeof submit);
    submit.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submit.commandBufferCount = 1;
    submit.pCommandBuffers = &command_buffer;
    if (vkQueueSubmit(queue, 1, &submit, VK_NULL_HANDLE) != VK_SUCCESS)
        goto done;
    if (vkQueueWaitIdle(queue) != VK_SUCCESS)
        goto done;
    if (vkMapMemory(device, memory, 0, VK_WHOLE_SIZE, 0, &mapped) != VK_SUCCESS)
        goto done;

    values = malloc(ELEMENTS * sizeof *values);
    if (!values) {
        vkUnmapMemory(device, memory);
        mapped = NULL;
        fail("malloc", "out of memory");
        goto done;
    }
    memcpy(values, mapped, ELEMENTS * sizeof *values);
    vkUnmapMemory(device, memory);
    mapped = NULL;
    for (i = 0; i < ELEMENTS; i++) {
        if (values[i] != pattern(i))
            mismatches++;
    }
    /* the fields are quoted and named so a harness can read one line back without guessing
     * where a device name that carries spaces ends */
    printf("vulkan-draw device=\"%s\" driver=\"%s\" elements=%u mismatches=%u\n", name, driver,
           (unsigned)ELEMENTS, (unsigned)mismatches);
    status = mismatches ? 1 : 0;

done:
    free(values);
    if (mapped)
        vkUnmapMemory(device, memory);
    if (buffer)
        vkDestroyBuffer(device, buffer, NULL);
    if (memory)
        vkFreeMemory(device, memory, NULL);
    if (command_pool)
        vkDestroyCommandPool(device, command_pool, NULL);
    if (pool)
        vkDestroyDescriptorPool(device, pool, NULL);
    if (pipeline)
        vkDestroyPipeline(device, pipeline, NULL);
    if (pipeline_layout)
        vkDestroyPipelineLayout(device, pipeline_layout, NULL);
    if (set_layout)
        vkDestroyDescriptorSetLayout(device, set_layout, NULL);
    if (shader)
        vkDestroyShaderModule(device, shader, NULL);
    free(code);
    vkDeviceWaitIdle(device);
    vkDestroyDevice(device, NULL);
    vkDestroyInstance(instance, NULL);
    return status;
}
