require 'yaml'

class Yaml_parser < Inspec.resource(1)
  name 'yaml_parser'

  attr_reader :params

  def initialize(path)
    y_content = inspec.file(path).content
    @params = YAML.load(y_content)
    puts @params
  end

end
