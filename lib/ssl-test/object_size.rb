require 'objspace'

module ObjectSize
  def self.size(obj)
    case obj
    when String
      obj.bytesize
    when Integer
      obj.size
    when Hash
      sum = 0
      obj.each do |key, val|
        sum += size(key)
        sum += size(val)
      end
      sum
    when Array
      obj.reduce(0) do |sum, val|
        sum + size(val)
      end
    else
      ObjectSpace.memsize_of(obj)
    end
  end
end